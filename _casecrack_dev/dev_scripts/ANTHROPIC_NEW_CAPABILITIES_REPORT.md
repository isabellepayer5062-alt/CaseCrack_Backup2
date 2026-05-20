# Anthropic Source Code — NEW Capabilities Not in CaseCrack

**Scope**: 8 directories analyzed: `tools/`, `state/`, `plugins/`, `utils/`, `types/`, `schemas/`, `server/`, `remote/`  
**Excluded** (already implemented): Reactive Compaction, Fork/Spawn, Speculative Execution, Token Budget Controller, FlushGate, Crash Recovery, DreamConsolidator, LLMMemoryRetriever, StallWatchdog, PostTurnOrchestrator, ResolveOnceGuard, CacheOptimizedForker, FuseCircuit, ConversationCostTracker

---

## 1. ADVISOR TOOL — Stronger Reviewer Model Delegation

**Source**: `utils/advisor.ts`  
**Category**: LLM Architecture / Model Composition

### What It Does
A base model (e.g., Sonnet) can call a stronger "advisor" model (e.g., Opus) via a zero-parameter `server_tool_use` block. The advisor sees the **entire conversation history** automatically — no parameters needed.

### Exact Algorithm
1. Base model emits `{ type: 'server_tool_use', name: 'advisor', input: {} }`
2. Server forwards full context to advisor model
3. Advisor returns one of:
   - `advisor_result` (text)
   - `advisor_redacted_result` (encrypted_content — privacy-preserving)
   - `advisor_tool_result_error` (error_code)

### Key Protocol Rules
- Call advisor **BEFORE** substantive work (writing code, committing to interpretations)
- Call advisor **WHEN DONE** — but first make deliverables durable (write files, stage changes)
- Call advisor when **STUCK** — recurring errors, non-converging approaches
- **Conflict Resolution**: If prior evidence contradicts advisor, don't silently switch — surface conflict in one more advisor call: *"I found X, you suggest Y, which constraint breaks the tie?"*
- On tasks >few steps: at least once before approach commitment, once before declaring done

### Config / Constants
- GrowthBook flag: `tengu_sage_compass`
- `AdvisorConfig`: `{ enabled, canUserConfigure, baseModel, advisorModel }`
- Env kill switch: `CLAUDE_CODE_DISABLE_ADVISOR_TOOL`
- First-party only (Bedrock/Vertex 400 on the beta header)
- Supported models: opus-4-6, sonnet-4-6

### Integration Value for CaseCrack
**HIGH**. Enables a two-tier reasoning architecture where the primary scan agent calls a stronger model for critical decisions (exploit validation, strategy pivots, final assessment). The conflict resolution protocol is directly applicable to hypothesis validation.

---

## 2. CRON SCHEDULER — Durable Scheduled Task Engine

**Source**: `utils/cronScheduler.ts`, `tools/ScheduleCronTool/CronCreateTool.ts`

### What It Does
Non-React scheduler core for `.claude/scheduled_tasks.json`. Supports durable (file-backed, survives restarts) and session-only tasks. Distributed lock prevents multi-process double-firing.

### State Machine
```
Lifecycle: poll getScheduledTasksEnabled() 
  → load tasks + watch file + start 1s timer 
  → on fire, call onFire(prompt) 
  → stop() tears down
```

### Key Data Structures
```typescript
type CronTask = {
  id: string
  cron: string          // 5-field cron expression, local time
  prompt: string        // What to execute
  recurring: boolean    // default true
  durable: boolean      // persists to file vs session-only
  permanent: boolean    // never ages out
  createdAt: number     // epoch ms
  lastFiredAt?: number
}
```

### Key Constants
- `MAX_JOBS = 50`
- `CHECK_INTERVAL_MS = 1000`
- `FILE_STABILITY_MS = 300`
- `LOCK_PROBE_INTERVAL_MS = 5000`
- `DEFAULT_MAX_AGE_DAYS` — auto-expiry for recurring non-permanent tasks
- Jitter config via GrowthBook for live-tuning during load spikes

### Algorithms
- **Lock Ownership**: `tryAcquireSchedulerLock()` uses PID liveness probe. Non-owning sessions re-probe every 5s for takeover on crash.
- **Missed Task Detection**: On startup, one-shot overdue tasks surfaced to user. Recurring tasks handled normally (fire immediately, reschedule forward).
- **Jittered Firing**: `jitteredNextCronRunMs()` prevents thundering herd at :00 boundaries.
- **Aging**: `isRecurringTaskAged(t, nowMs, maxAgeMs)` — recurring tasks older than maxAgeMs auto-delete.
- **In-Flight Dedup**: `Set<string>` prevents double-fire if interval ticks before `removeCronTasks` completes.

### Integration Value for CaseCrack
**MEDIUM-HIGH**. Enables scheduled re-scans, periodic vulnerability checks, time-based strategy escalation. The lock mechanism prevents duplicate scan execution in multi-process deployments.

---

## 3. SIDE QUERY — Out-of-Band LLM Calls

**Source**: `utils/sideQuery.ts`

### What It Does
Lightweight API wrapper for LLM queries **outside** the main conversation loop. Handles OAuth fingerprinting, attribution headers, model normalization, beta header injection, thinking budget control, and structured outputs.

### Use Cases
- Permission explainer (should this tool use be allowed?)
- Session search (find relevant past context)
- Model validation (test model availability)
- Classifiers (bash safety, transcript analysis)
- Any out-of-band reasoning that shouldn't pollute the main context

### Key Interface
```typescript
type SideQueryOptions = {
  model: string
  system?: string | TextBlockParam[]
  messages: MessageParam[]
  tools?: Tool[] | BetaToolUnion[]
  tool_choice?: ToolChoice
  output_format?: BetaJSONOutputFormat  // structured outputs
  max_tokens?: number                    // default: 1024
  maxRetries?: number                    // default: 2
  temperature?: number
  thinking?: number | false              // budget or disabled
  stop_sequences?: string[]
  querySource: QuerySource               // analytics attribution
  signal?: AbortSignal
  skipSystemPromptPrefix?: boolean       // for internal classifiers
}
```

### Key Detail
System prompt blocks are structured as separate `TextBlockParam` entries to prevent server-side parsing from including system content in `cc_entrypoint`. Attribution header always in its own block.

### Integration Value for CaseCrack
**HIGH**. CaseCrack's agents should use side queries for: vulnerability classification, exploit validation checks, strategy recommendations — all without polluting the main scan context window.

---

## 4. CLASSIFIER AUTO-APPROVAL SYSTEM

**Source**: `utils/classifierApprovals.ts`

### What It Does
Two independent classifier systems that can auto-approve tool uses without user confirmation:

1. **Bash Classifier** (`feature('BASH_CLASSIFIER')`) — Matches bash command patterns against rules
2. **Transcript Classifier** (`feature('TRANSCRIPT_CLASSIFIER')`) — Analyzes full transcript context for auto-mode

### State Tracking
```typescript
// Per tool-use approval tracking
Map<toolUseID, { classifier: 'bash' | 'auto-mode', matchedRule?, reason? }>

// "Currently checking" state for UI spinners
Set<toolUseID>  // with Signal-based subscriber notification
```

### Integration Value for CaseCrack
**MEDIUM**. Enables auto-approval of safe scan operations (e.g., DNS lookups, passive recon) while requiring human approval for destructive operations (exploitation, brute force). The two-classifier approach (command-level + context-level) provides defense-in-depth.

---

## 5. QUERY GUARD STATE MACHINE

**Source**: `utils/QueryGuard.ts`

### What It Does
Synchronous state machine for query lifecycle, compatible with React's `useSyncExternalStore`. Prevents re-entry during async gaps between queue dequeue and query execution.

### State Machine
```
idle → dispatching  (reserve)
dispatching → running  (tryStart)
idle → running  (tryStart, direct user submit)
running → idle  (end / forceEnd)
dispatching → idle  (cancelReservation)
```

### Key Innovation: Generation-Based Stale Detection
```typescript
end(generation: number): boolean {
  // Returns false if a newer query started (stale finally block)
  if (this._generation !== generation) return false
}

forceEnd(): void {
  // Increments generation so stale finally blocks see mismatch
  ++this._generation
}
```

### Integration Value for CaseCrack
**MEDIUM**. The generation-based stale detection pattern is valuable for CaseCrack's tool execution pipelines — prevents stale callbacks from interfering with newer operations. The three-state machine pattern would improve scan phase coordination.

---

## 6. WORKLOAD CONTEXT VIA ASYNCLOCALSTORAGE

**Source**: `utils/workloadContext.ts`

### What It Does
Turn-scoped workload tagging using Node.js `AsyncLocalStorage`. Tags (e.g., `'cron'`) survive across all awaits in a chain, isolated from the parent context.

### Critical Design Decision
```typescript
// ALWAYS establishes a new context boundary, even for undefined
// Previous pass-through implementation leaked cron context through:
// queryGuard.end() → notify() → React subscriber → scheduled re-render
// captures ALS at scheduling time → useQueueProcessor → executeQueuedInput
export function runWithWorkload<T>(workload: string | undefined, fn: () => T): T {
  return workloadStorage.run({ workload }, fn)
}
```

### Why Not a Global Variable?
Void-detached background agents (`executeForkedSlashCommand`, `AgentTool`) yield at their first `await`. Parent turn's synchronous `finally` block runs BEFORE the detached closure resumes. A global `setWorkload('cron')` is deterministically clobbered.

### Integration Value for CaseCrack
**MEDIUM**. CaseCrack's parallel agent workers need workload context isolation. AsyncLocalStorage prevents cross-contamination between concurrent scan phases running in the same process.

---

## 7. MAILBOX + MESSAGE QUEUE SYSTEM

**Source**: `utils/mailbox.ts`, `utils/messageQueueManager.ts`, `utils/queueProcessor.ts`

### What It Does
Three-layer inter-agent communication system:

### Layer 1: Mailbox (mailbox.ts)
```typescript
class Mailbox {
  queue: Message[]
  waiters: Waiter[]  // { fn: predicate, resolve: Promise resolver }
  
  send(msg): void    // Resolves waiting receiver immediately OR queues
  poll(fn): Message   // Non-blocking, returns undefined if no match
  receive(fn): Promise<Message>  // Blocks via Promise until match arrives
}
```
Message sources: `'user' | 'teammate' | 'system' | 'tick' | 'task'`

### Layer 2: Priority Command Queue (messageQueueManager.ts)
```typescript
type QueuePriority = 'now' | 'next' | 'later'
// now > next > later, FIFO within same priority

enqueue(command)                    // defaults priority='next'
enqueuePendingNotification(command) // defaults priority='later'
dequeue(filter?)                    // returns highest-priority match
dequeueAllMatching(predicate)       // drain all matching
peek(filter?)                       // non-destructive read
```
- `useSyncExternalStore` compatible (frozen snapshot recreation on mutation)
- Session-storage backed operation logging

### Layer 3: Queue Processor (queueProcessor.ts)
```
Slash commands → processed individually
Bash-mode commands → processed individually (per-command error isolation)
Other commands → batched by same mode (drain all with target mode at once)
```
- Main-thread filtering: `cmd.agentId === undefined` prevents subagent stalls

### Integration Value for CaseCrack
**HIGH**. The three-layer architecture (mailbox → priority queue → batch processor) is directly applicable to CaseCrack's multi-agent scan coordination. Priority queuing prevents task-notification flooding from starving user commands.

---

## 8. EFFORT SYSTEM — Dynamic Compute Budget

**Source**: `utils/effort.ts`

### What It Does
4-tier effort control system: `low | medium | high | max`

### Key Rules
- **max** is Opus 4.6 only (other models return API error)
- Numeric values (0-1 range) are session-scoped, never persisted
- **Persistence chain**: env `CLAUDE_CODE_EFFORT_LEVEL` → `appState.effortValue` → model default
- `'unset'`/`'auto'` env value clears effort (sends no parameter)

### Picker Persistence Logic
```typescript
function resolvePickerEffortPersistence(
  picked, modelDefault, priorPersisted, toggledInPicker
): EffortLevel | undefined {
  const hadExplicit = priorPersisted !== undefined || toggledInPicker
  return hadExplicit || picked !== modelDefault ? picked : undefined
}
```

### Integration Value for CaseCrack
**MEDIUM**. CaseCrack could use effort levels to control LLM compute budget per scan phase — low effort for initial recon, high/max for complex exploit reasoning.

---

## 9. CONTEXT ANALYSIS + SUGGESTIONS ENGINE

**Source**: `utils/contextAnalysis.ts`, `utils/contextSuggestions.ts`

### What It Does
Analyzes conversation context token distribution and generates optimization suggestions.

### Context Analysis (contextAnalysis.ts)
```typescript
type TokenStats = {
  toolRequests: Map<string, number>    // tokens per tool type (requests)
  toolResults: Map<string, number>     // tokens per tool type (results)
  humanMessages: number
  assistantMessages: number
  localCommandOutputs: number
  attachments: Map<string, number>     // by attachment type
  duplicateFileReads: Map<string, { count: number; tokens: number }>
  total: number
}
```
**Duplicate file read detection**: Tracks file path per Read tool_use_id, counts re-reads, calculates wasted tokens as `averageTokensPerRead × (count - 1)`.

### Context Suggestions (contextSuggestions.ts)
Thresholds:
```
LARGE_TOOL_RESULT_PERCENT = 15    // tool results > 15% of context
LARGE_TOOL_RESULT_TOKENS = 10_000
READ_BLOAT_PERCENT = 5
NEAR_CAPACITY_PERCENT = 80
MEMORY_HIGH_PERCENT = 5
MEMORY_HIGH_TOKENS = 5_000
```

Tool-specific advice:
- **Bash**: "Pipe through head/tail/grep to reduce result size"
- **Read**: "Use offset/limit parameters"  
- **Grep**: "Add specific patterns, use glob/type parameters"
- **WebFetch**: "Extract only specific information needed"
- **Memory**: "Use /memory to review and prune stale entries"

### Integration Value for CaseCrack
**HIGH**. CaseCrack's context windows fill rapidly during scans. Duplicate read detection + per-tool token tracking would enable intelligent context pruning. The suggestions engine pattern is directly applicable to scan output optimization.

---

## 10. ULTRAPLAN/ULTRAREVIEW KEYWORD TRIGGER ENGINE

**Source**: `utils/ultraplan/keyword.ts`

### What It Does
Smart keyword detection that triggers multi-agent planning workflows (ultraplan) or review workflows (ultrareview) from natural language input.

### Skip Rules (False Positive Prevention)
```
1. Inside paired delimiters: backticks, "quotes", <tags>, {braces}, [brackets], (parens)
2. Single quotes → apostrophe disambiguation (opening must be preceded by non-word)
3. Path/identifier context: preceded/followed by /, \, - or followed by .ext
4. Followed by ? (question about feature, not invocation)
5. Slash command input (starts with /)
```

### Apostrophe vs Quote Algorithm
```
Opening quote valid if: preceded by non-word char OR at start
Closing quote valid if: followed by non-word char OR at end
"let's ultraplan it's" → TRIGGERS (apostrophes, not quotes)
'ultraplan' → DOES NOT TRIGGER (inside single quotes)
```

### Grammatical Keyword Replacement
```typescript
// "please ultraplan this" → "please plan this"
// Preserves user's casing of the "plan" suffix
replaceUltraplanKeyword(text): strips "ultra" prefix from first trigger
```

### Integration Value for CaseCrack
**LOW-MEDIUM**. The delimiter-aware keyword detection algorithm is reusable for CaseCrack's command parsing (e.g., detecting scan directives in natural language while ignoring them in code blocks, URLs, file paths).

---

## 11. TOOL POOL — Merge, Dedup & Coordinator Filter

**Source**: `utils/toolPool.ts`

### What It Does
Merges multiple tool sources with deduplication, ensuring prompt cache stability.

### Key Algorithm: Cache-Stable Ordering
```typescript
// Partition-sort: built-ins MUST be contiguous prefix for server's cache policy
const [mcp, builtIn] = partition(uniqBy([...initialTools, ...assembled], 'name'), isMcpTool)
const tools = [...builtIn.sort(byName), ...mcp.sort(byName)]
```
Built-in tools sorted alphabetically first, then MCP tools sorted alphabetically. This ensures the ~11K-token tool block has stable byte-level content for prompt caching.

### Coordinator Mode Filtering
```typescript
// Coordinator only gets: COORDINATOR_MODE_ALLOWED_TOOLS + PR activity subscription tools
function applyCoordinatorToolFilter(tools: Tools): Tools {
  return tools.filter(t => 
    COORDINATOR_MODE_ALLOWED_TOOLS.has(t.name) || isPrActivitySubscriptionTool(t.name)
  )
}
```

### Integration Value for CaseCrack
**MEDIUM**. The cache-stable ordering pattern is valuable for CaseCrack's tool definition blocks. Coordinator mode filtering maps to CaseCrack's agent role restrictions.

---

## 12. TOOL SCHEMA CACHE — Session-Scoped Schema Memoization

**Source**: `utils/toolSchemaCache.ts`

### What It Does
Prevents tool schema re-rendering from busting the server's prompt cache.

### Problem Solved
Tool schemas render at server position 2 (before system prompt). Any byte-level change busts the entire ~11K-token tool block AND everything downstream. Sources of churn:
- GrowthBook gate flips
- MCP reconnects
- Dynamic content in `tool.prompt()`

### Solution
```typescript
const TOOL_SCHEMA_CACHE = new Map<string, CachedSchema>()
// Locks schema bytes at first render
// Mid-session GB refreshes no longer bust the cache
```
Lives in leaf module to avoid circular dependencies (auth.ts → api.ts cycle).

### Integration Value for CaseCrack
**MEDIUM**. CaseCrack's tool definitions should be memoized per-session to avoid prompt cache invalidation when tool configurations change mid-scan.

---

## 13. FILE READ CACHE — Mtime-Based Invalidation

**Source**: `utils/fileReadCache.ts`

### What It Does
In-memory file cache with automatic mtime-based invalidation for FileEditTool operations.

### Key Design
```typescript
class FileReadCache {
  cache: Map<string, { content: string, encoding: BufferEncoding, mtime: number }>
  maxCacheSize = 1000
  
  readFile(filePath): { content, encoding }  // CRLF→LF normalization
  invalidate(filePath): void
  clear(): void
}
```
- Cache key = file path
- Validity check = `stats.mtimeMs` comparison
- Eviction = FIFO (delete first inserted key when size > 1000)
- Encoding detection = automatic per file

### Integration Value for CaseCrack
**LOW-MEDIUM**. Useful for CaseCrack's file analysis tools that re-read the same files within a scan session.

---

## 14. SIGNAL PRIMITIVE — Lightweight Event System

**Source**: `utils/signal.ts`

### What It Does
Replaces the ~8-line `Set<listener> + subscribe + notify` boilerplate duplicated ~15× across the codebase.

```typescript
type Signal<Args extends unknown[] = []> = {
  subscribe: (listener: (...args: Args) => void) => () => void  // returns unsubscribe
  emit: (...args: Args) => void
  clear: () => void
}
```

### Usage Pattern
```typescript
const changed = createSignal<[SettingSource]>()
export const subscribe = changed.subscribe
// later: changed.emit('userSettings')
```

### Integration Value for CaseCrack
**MEDIUM**. Clean event dispatch pattern. Used as foundation by Mailbox, ClassifierApprovals, QueryGuard, MessageQueueManager.

---

## 15. ACTIVITY MANAGER — User vs CLI Time Tracking

**Source**: `utils/activityManager.ts`

### What It Does
Separates user interaction time from CLI (tool execution / AI response) time with overlap deduplication.

```typescript
class ActivityManager {
  USER_ACTIVITY_TIMEOUT_MS = 5000
  
  recordUserActivity()              // Records if not CLI-active
  startCLIActivity(operationId)     // Tracked via Set for overlap dedup
  endCLIActivity(operationId)       // Last-out triggers time recording
  trackOperation(id, fn)            // Async wrapper
}
```

### Key Design
- CLI takes precedence over user activity (no double-counting)
- Overlapping operations: only first-in / last-out triggers timer changes
- Crash protection: if operationId already exists on start, force-ends previous (underestimate vs overestimate)

### Integration Value for CaseCrack
**LOW-MEDIUM**. Useful for scan analytics — separating user think time from tool execution time for performance optimization.

---

## 16. HOOK SYSTEM — 4-Type Event Architecture

**Source**: `schemas/hooks.ts`, `types/hooks.ts`

### What It Does
Extensible event hook system with 4 execution types and 15+ event types.

### Hook Types
| Type | Trigger | Response |
|------|---------|----------|
| `BashCommandHook` | Shell command | stdout/stderr, exit code |
| `PromptHook` | Prompt template | Text expansion |
| `HttpHook` | HTTP endpoint | JSON response |
| `AgentHook` | Agent delegation | Agent output |

### Event Types
```
PreToolUse, PostToolUse, PostToolUseFailure,
UserPromptSubmit, SessionStart, Setup,
SubagentStart, PermissionDenied, Notification,
PermissionRequest, Elicitation, ElicitationResult,
CwdChanged, FileChanged, WorktreeCreate
```

### Hook Features
- `once: boolean` — fire once, then auto-remove
- `async: boolean` — run in background, don't block
- `asyncRewake: boolean` — wake model on exit code 2
- `timeout: number` — execution timeout
- `statusMessage: string` — UI status during execution

### IfCondition Permission Filter
```typescript
// Rule syntax: "Bash(git *)" matches bash commands starting with "git "
IfConditionSchema = z.object({
  tool_name: z.string(),
  input_pattern: z.string().optional()
})
```

### Prompt Elicitation Protocol
```typescript
promptRequestSchema = {
  question: string,
  options: Array<{ value: string, label?: string }>,
  required: boolean
}
```

### Integration Value for CaseCrack
**HIGH**. CaseCrack can use hooks for: pre-tool-use validation (prevent dangerous commands), post-tool-use analysis (auto-classify findings), session start initialization, file change monitoring during scans. The async rewake pattern (exit code 2 = notify agent) is directly applicable to long-running scan tools.

---

## 17. PLUGIN ARCHITECTURE — Extensible Module System

**Source**: `types/plugin.ts`, `plugins/builtinPlugins.ts`

### What It Does
Full plugin lifecycle: discovery → validation → loading → error handling.

### Plugin Definition
```typescript
type BuiltinPluginDefinition = {
  name: string
  description: string
  skills: SkillDefinition[]           // Agent capabilities
  hooks: HooksConfig                   // Event hooks
  mcpServers: Record<string, McpServerConfig>  // MCP servers
  isAvailable: () => boolean           // Runtime availability check
  defaultEnabled: boolean
}

type LoadedPlugin = {
  manifest: PluginManifest
  path: string
  source: 'builtin' | 'marketplace' | 'local'
  commandsPath?: string
  agentsPaths?: string[]
  skillsPaths?: string[]
  outputStylesPaths?: string[]
  hooksConfig?: HooksConfig
  mcpServers?: Record<string, McpServerConfig>
  lspServers?: Record<string, LspServerConfig>
}
```

### 22+ Error Types (discriminated union)
```
path-not-found, git-auth-failed, manifest-parse-error, 
mcp-config-invalid, lsp-server-crashed, 
marketplace-blocked-by-policy, dependency-unsatisfied,
hook-execution-timeout, ...
```

### Integration Value for CaseCrack
**MEDIUM**. CaseCrack could use a plugin system for: custom scanner modules, exploit technique plugins, reporting format plugins, external tool integrations. The 22-type error union ensures comprehensive error handling.

---

## 18. REMOTE SESSION MANAGEMENT — CCR Protocol

**Source**: `remote/RemoteSessionManager.ts`, `remote/SessionsWebSocket.ts`, `remote/sdkMessageAdapter.ts`, `remote/remotePermissionBridge.ts`

### What It Does
Manages Cloud Container Runtime (CCR) sessions over WebSocket with permission bridging.

### Key Constants
```typescript
RECONNECT_DELAY_MS = 2000
MAX_RECONNECT_ATTEMPTS = 5
PING_INTERVAL_MS = 30000
MAX_SESSION_NOT_FOUND_RETRIES = 3
PERMANENT_CLOSE_CODES = Set([4003])  // unauthorized
```

### Permission Bridge
```typescript
// Creates synthetic AssistantMessage for remote permission requests
// createToolStub() - minimal Tool stub for tools not loaded locally (MCP tools from remote)
function createToolStub(toolName: string): Tool {
  // Bridge between remote tool definitions and local permission system
}
```

### Session States
```
'starting' | 'running' | 'detached' | 'stopping' | 'stopped'
```

### Session Persistence
```typescript
// SessionIndex: persistent metadata in ~/.claude/server-sessions.json
// Enables resume across restarts
type SessionIndex = {
  sessionId: string
  workspace: string
  createdAt: number
  lastActive: number
}
```

### Integration Value for CaseCrack
**MEDIUM-HIGH**. Remote session management enables: headless scan execution in containers, distributed agent coordination, session resume after crashes/restarts. The permission bridge pattern is valuable for remote tool approval workflows.

---

## 19. DIRECT CONNECT SESSION PROTOCOL

**Source**: `server/createDirectConnectSession.ts`, `server/directConnectManager.ts`, `server/types.ts`

### What It Does
WebSocket-based direct session management for local server mode.

### Server Config
```typescript
type ServerConfig = {
  port: number
  host: string
  authToken: string
  unix?: string         // Unix socket path
  idleTimeoutMs: number
  maxSessions: number
  workspace: string
}
```

### Message Filtering
```typescript
// DirectConnectSessionManager filters OUT these message types:
const FILTERED = ['control_response', 'keep_alive', 'control_cancel_request',
  'streamlined_text', 'streamlined_tool_use_summary', 'post_turn_summary']
```

### Integration Value for CaseCrack
**MEDIUM**. Direct connect enables local SDK-to-agent communication without cloud round-trips. The message filtering pattern is useful for CaseCrack's scan output optimization.

---

## 20. CIRCULAR BUFFER — Fixed-Size Rolling Window

**Source**: `utils/CircularBuffer.ts`

### What It Does
```typescript
class CircularBuffer<T> {
  constructor(capacity: number)
  add(item: T): void       // auto-evicts oldest
  addAll(items: T[]): void
  getRecent(count: number): T[]
  toArray(): T[]            // oldest to newest
  clear(): void
  length(): number
}
```

### Integration Value for CaseCrack
**LOW-MEDIUM**. Useful for rolling windows of recent findings, scan events, or performance metrics without unbounded memory growth.

---

## 21. DEFERRED TOOL DISCOVERY ENGINE

**Source**: `tools/ToolSearchTool/ToolSearchTool.ts`

### What It Does
Lazy tool loading with keyword-based discovery. Tools not loaded at startup are discoverable at runtime.

### Algorithm
1. Agent calls `ToolSearch` with keywords or `select:<tool_name>`
2. Tool descriptions are memoized (cache invalidated on tool set changes)
3. `parseToolName()` handles MCP tools (`mcp__server__action`) and CamelCase
4. Pre-compiled word-boundary regexes for search terms

### Integration Value for CaseCrack
**MEDIUM**. CaseCrack could lazily load exploit modules, scanner tools, and analysis capabilities on-demand rather than loading everything at startup.

---

## 22. WORKTREE ISOLATION — Git-Based Session Sandboxing

**Source**: `tools/EnterWorktreeTool/EnterWorktreeTool.ts`

### What It Does
Creates isolated git worktree and switches the entire session into it.

### Post-Switch Cleanup
```
1. Resolves to main repo root before worktree creation
2. Clears system prompt sections
3. Clears memory file caches
4. Clears plans directory cache
5. Saves worktree state for session persistence
```

### Integration Value for CaseCrack
**LOW**. More relevant for development agents than security scanning. However, the pattern of session state invalidation on context switch is generally useful.

---

## 23. LSP INTEGRATION — Language Server Protocol Tool

**Source**: `tools/LSPTool/LSPTool.ts`

### What It Does
9 LSP operations for code intelligence:
```
goToDefinition, findReferences, hover, documentSymbol,
workspaceSymbol, goToImplementation, prepareCallHierarchy,
incomingCalls, outgoingCalls
```

### Key Constants & Security
- `MAX_LSP_FILE_SIZE_BYTES = 10_000_000` (10MB)
- **UNC Path Security**: Skips UNC paths to prevent NTLM credential leaks

### Integration Value for CaseCrack
**MEDIUM**. LSP operations enable deep source code analysis for vulnerability detection — finding all references to a vulnerable function, tracing call hierarchies for taint analysis.

---

## 24. GIT OPERATION TRACKING

**Source**: `tools/shared/gitOperationTracking.ts`

### What It Does
Detects git operations from command output using regex patterns.

```typescript
type GitOperationResult = {
  operation: 'commit' | 'push' | 'cherry-pick' | 'merge' | 'rebase' | 'gh-pr'
  commitSHA?: string
  pushBranch?: string
  prNumber?: string
  prUrl?: string
}
```
Supports git global options between `git` and subcommand (e.g., `git -c user.name=x commit`).

### Integration Value for CaseCrack
**LOW**. Relevant for source code audit scans that need to track repository state changes.

---

## 25. STRUCTURED OUTPUT TOOL — Schema-Validated JSON Output

**Source**: `tools/SyntheticOutputTool/SyntheticOutputTool.ts`

### What It Does
Forces LLM to produce schema-valid JSON output for non-interactive SDK/CLI use.

### Key Innovation: WeakMap Schema Caching
```typescript
// Identity-based caching using WeakMap
// Same schema object reference → same compiled Ajv validator
// 80-call workflows: ~110ms → ~4ms Ajv overhead
const schemaCache = new WeakMap<object, ValidateFunction>()
```

### Integration Value for CaseCrack
**MEDIUM**. Ensures scan findings conform to structured schemas. The WeakMap caching pattern is valuable for repeated schema validation across many findings.

---

## 26. FAST MODE — Tiered Execution Speed

**Source**: `utils/fastMode.ts`

### What It Does
Feature toggle for faster (potentially lower-quality) execution mode.

### Availability Gates (checked in order)
1. `CLAUDE_CODE_DISABLE_FAST_MODE` env var
2. GrowthBook kill switch (`tengu_penguins_off`)
3. Bundled mode requirement (flag-gated)
4. SDK opt-in check
5. Subscription tier check (free users excluded)
6. Extra usage billing check (OAuth users)
7. 3P auth check
8. Network error detection

### Disabled Reason Messages
```
'free' → "Fast mode requires a paid subscription"
'preference' → "Fast mode has been disabled by your organization"
'extra_usage_disabled' → "Fast mode requires extra usage billing"
'network_error' → "Fast mode unavailable due to network connectivity issues"
```

### Integration Value for CaseCrack
**LOW-MEDIUM**. The tiered execution speed concept maps to CaseCrack's scan intensity levels. The multi-gate availability check pattern is a solid reference for feature gating.

---

## 27. IDLE TIMEOUT MANAGER

**Source**: `utils/idleTimeout.ts`

### What It Does
Auto-exits the process after configurable idle duration (SDK mode).

```typescript
// Env: CLAUDE_CODE_EXIT_AFTER_STOP_DELAY (ms)
// Checks continuous idle state before exiting
function createIdleTimeoutManager(isIdle: () => boolean): { start, stop }
```

### Key Detail
Uses a single `setTimeout` — checks if `isIdle()` is STILL true when the timer fires (not just when started). Prevents premature exit if activity occurred mid-timer.

### Integration Value for CaseCrack
**LOW**. The re-check-on-fire pattern prevents false shutdowns and is applicable to CaseCrack's headless scan mode.

---

## 28. FINGERPRINT COMPUTATION — OAuth Attribution

**Source**: `utils/fingerprint.ts`

### What It Does
3-character hex fingerprint for API attribution/validation.

### Algorithm
```
chars = msg[4] + msg[7] + msg[20]  (use "0" if index missing)
input = SALT + chars + version
fingerprint = SHA256(input)[:3]
```
- Salt: `'59cf53e54c78'` (hardcoded, must match backend)
- Coordinated across 1P and 3P APIs (Bedrock, Vertex, Azure)

### Integration Value for CaseCrack
**LOW**. The fingerprinting technique itself is a reference for API attribution. Not directly needed for CaseCrack.

---

## 29. SWARM TEAM ORCHESTRATION

**Source**: `tools/TeamCreateTool/TeamCreateTool.ts`, `tools/shared/spawnMultiAgent.ts`

### What It Does
Creates multi-agent teams with enforced constraints.

### Constraints
- **One team per leader** restriction
- Deterministic agent ID generation from team name
- Backend detection: tmux → iTerm2 → in-process (fallback chain)
- Model inheritance: `'inherit'` alias uses leader's model

### Spawning Infrastructure
```typescript
type SpawnTeammateConfig = {
  invokingRequestId: string  // Lineage tracing
  // ... model, role, etc.
}

function getDefaultTeammateModel(): string {
  // Fallback: user config → leader model → hardcoded default
}
```

### Team = Project = TaskList
- Each team creates a corresponding task list directory
- Filesystem-based metadata storage (TeamFile with members array)
- Session-end cleanup registration

### Integration Value for CaseCrack
**MEDIUM-HIGH**. The one-team-per-leader constraint and deterministic agent IDs are directly applicable to CaseCrack's multi-agent scanning. Model inheritance enables cost-efficient team composition.

---

## 30. REMOTE TRIGGER SYSTEM

**Source**: `tools/RemoteTriggerTool/RemoteTriggerTool.ts`

### What It Does
CRUD + run for remote agent triggers via Anthropic API.

```typescript
// Actions: list, get, create, update, run
// Beta header: 'ccr-triggers-2026-01-30'
// Feature gates: GrowthBook 'tengu_surreal_dali' + policy 'allow_remote_sessions'
```

### Integration Value for CaseCrack
**LOW-MEDIUM**. Remote triggers could enable: scheduled scans from external systems, webhook-triggered assessments, CI/CD pipeline integration.

---

## PRIORITY RANKING FOR IMPLEMENTATION

### Tier 1 — High Value, Novel Architecture
1. **Advisor Tool** (#1) — Two-tier model composition with conflict resolution
2. **Side Query** (#3) — Out-of-band LLM calls without context pollution
3. **Hook System** (#16) — 4-type event architecture with 15+ events
4. **Mailbox + Queue System** (#7) — Three-layer priority communication
5. **Context Analysis + Suggestions** (#9) — Token optimization with savings estimates

### Tier 2 — Solid Infrastructure
6. **Cron Scheduler** (#2) — Durable scheduled tasks with distributed lock
7. **Classifier Auto-Approval** (#4) — Two-classifier safety system
8. **Query Guard State Machine** (#5) — Generation-based stale detection
9. **Swarm Team Orchestration** (#29) — Multi-agent teams with constraints
10. **Remote Session Management** (#18) — CCR protocol with permission bridging

### Tier 3 — Useful Patterns
11. **Tool Pool Cache-Stable Ordering** (#11) — Prompt cache optimization
12. **Tool Schema Cache** (#12) — Session-scoped schema memoization
13. **Effort System** (#8) — Dynamic compute budget
14. **Workload Context** (#6) — AsyncLocalStorage isolation
15. **Deferred Tool Discovery** (#21) — Lazy tool loading

### Tier 4 — Reference Implementations
16-30. CircularBuffer, FileReadCache, Signal, ActivityManager, IdleTimeout, FastMode, Fingerprint, UltraplanKeyword, WorktreeIsolation, LSP Integration, GitTracking, StructuredOutput, RemoteTriggers, DirectConnect, Heatmap
