# CaseCrack Venator — Workspace Redesign Specification
**Document Status:** v1.0 Draft — April 21, 2026  
**Scope:** `recon-dashboard-body.html` · `recon-dashboard.css` · `recon-dashboard.js`  
**Constraint class:** Controlled structural refactor — not a rewrite

---

## Table of Contents
1. [Design Mandates](#1-design-mandates)
2. [Architecture Overview](#2-architecture-overview)
3. [Panel Role Taxonomy](#3-panel-role-taxonomy)
4. [Panel Catalog](#4-panel-catalog)
5. [Interaction Model](#5-interaction-model)
6. [Analysis Context System](#6-analysis-context-system)
7. [Persistence Architecture](#7-persistence-architecture)
8. [Console System](#8-console-system)
9. [Focus Mode Bias System](#9-focus-mode-bias-system)
10. [Layout Intelligence System](#10-layout-intelligence-system)
11. [Visual Specification](#11-visual-specification)
12. [Workspace Presets](#12-workspace-presets)
13. [Widget Registry Schema](#13-widget-registry-schema)
14. [Rollout Plan — 6 Stages](#14-rollout-plan--6-stages)
15. [Engineering Rules (Hard Constraints)](#15-engineering-rules-hard-constraints)

---

## 1. Design Mandates

These are non-negotiable constraints. If any implementation step violates one, stop and re-plan.

| # | Mandate | Reason |
|---|---------|--------|
| M1 | **Wrap existing render targets. Never replace them.** | `recon-dashboard.js` is ~26,000 lines with 275 `ccIcon()` calls and 15 dirty-flag render groups. Replacing mount points breaks everything. |
| M2 | **Preserve all existing DOM ids.** | Render functions are bound to ids (`$('findingsList')`, `$('consoleFeed')`, etc.). Any id rename breaks the render loop silently. |
| M3 | **Panel chrome wraps existing containers — existing containers do not wrap panel chrome.** | Wrapping direction defines the DOM hierarchy. Reversing it requires rewriting every `querySelector`-based render call. |
| M4 | **The dirty-flag / `renderAll()` cycle is immutable.** | It is the engine's heartbeat. The workspace layer plugs into it (by skipping hidden panels); it never replaces it. |
| M5 | **Agent Chat is permanently docked. It is not removable.** | Removing it degrades workflow and product identity. It may be collapsed but not removed from the panel registry. |
| M6 | **Do not add a framework (React, Vue, Angular).** | The entire codebase is vanilla JS. A framework insertion at this stage is a rewrite via the back door. |
| M7 | **One layout manager — not one per preset.** | Presets are data (JSON snapshots). The layout manager reads them. Multiple layout managers = fragmentation hell. |
| M8 | **"Let's just rewrite this one panel" is forbidden.** | Scope will explode every time. If a panel needs interior changes, those happen in a separate, later phase after the workspace layer is stable. |

---

## 2. Architecture Overview

### 2.1 Layer Diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│  HEADER (immutable — infra indicators, mode toggle, WS status)      │
├─────────────────────────────────────────────────────────────────────┤
│  CONTROL BAR (immutable — target input, phase selector, run/stop)   │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  WORKSPACE GRID CONTAINER  ← new layer                             │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │  PANEL SHELL  [drag-handle] [title] [role-chip] [actions]    │  │
│  │  ┌────────────────────────────────────────────────────────┐  │  │
│  │  │  EXISTING PANEL CONTENT  (DOM ids unchanged)           │  │  │
│  │  │  e.g. <div id="findingsList">...</div>                 │  │  │
│  │  └────────────────────────────────────────────────────────┘  │  │
│  │  [resize-handle-right] [resize-handle-bottom]                │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                                                                     │
├─────────────────────────────────────────────────────────────────────┤
│  AGENT CHAT DOCK (permanently pinned — bottom-right anchor)         │
└─────────────────────────────────────────────────────────────────────┘
```

### 2.2 Core Subsystems

| Subsystem | Location | Responsibility |
|-----------|----------|----------------|
| `CC_PANELS` registry | `recon-dashboard.js` | Authoritative panel definitions (id, role, deps, render fn, constraints) |
| `CC_LAYOUT` manager | `recon-dashboard.js` | Reads registry, builds workspace grid, manages panel state |
| `CC_CTX` analysis context | `recon-dashboard.js` | Global shared filter object, subscription bus, event emission |
| `CC_PERSIST` persistence stack | `recon-dashboard.js` | Priority-ordered layout + filter state hydration / dehydration |
| Workspace grid CSS | `recon-dashboard.css` | Panel shell, drag regions, resize handles, role styles, focus mode |

### 2.3 Execution Order on Page Load

```
1. CC_PANELS registry initialized (static object, no DOM access)
2. CC_PERSIST.hydrate() → resolves layout from priority stack
3. CC_LAYOUT.mount() → builds panel shells around existing containers
4. CC_CTX.init() → subscribes panels to analysis context slices
5. Existing renderAll() / WS connection proceeds unchanged
6. CC_LAYOUT.applyLayout(resolved) → positions / sizes panels
```

### 2.4 What Does NOT Change

- All `state.*` fields
- All `markDirty()` calls
- All `renderAll()` dispatch logic
- All render functions (`renderFindings`, `_renderExploitGraphPanel`, etc.)
- All `state_snapshot` / `state_diff` WebSocket handlers
- All existing DOM ids inside panel content
- The `initSplitters()` function (deprecated but not removed until Stage 3)
- The `conResizeHandle` vertical console resize (superseded by panel resize in Stage 2, removed in Stage 3)

---

## 3. Panel Role Taxonomy

Not all panels are equal. Role determines default behavior, layout constraints, interaction priority, and preset slot assignment.

### Role Definitions

| Role | Code | Description | Key Properties |
|------|------|-------------|----------------|
| **Primary** | `primary` | Analysis surfaces. These are the reason the dashboard exists. | Focus-biased, full-size capable, keyboard-navigable, always visible in default preset |
| **Secondary** | `secondary` | Supporting data panels. Provide context for primary surfaces. | Can be compacted, auto-hide allowed, linked to primary selection |
| **Utility** | `utility` | System + operational panels. Infrastructure of the workflow. | Anchorable (edge-dock), not freely draggable in compact presets, always-on option |

### Role Behavior Matrix

| Behavior | Primary | Secondary | Utility |
|----------|---------|-----------|---------|
| Draggable (free) | ✓ | ✓ | Anchored only |
| Resize both axes | ✓ | ✓ | Horizontal only |
| Focusable (fullscreen-bias) | ✓ | ✗ | ✗ |
| Auto-expand on event spike | ✓ | ✗ | ✗ |
| Removable by user | ✓ | ✓ | Collapse only |
| Snap to related panels | ✓ | ✓ | Edge snap |
| Participates in linked analysis | ✓ (both emit + receive) | ✓ (receive only) | ✓ (emit only) |
| Dim when another is focused | ✓ | ✓ | ✗ |

---

## 4. Panel Catalog

All 19 panels defined. Each entry maps to existing render infrastructure.

---

### 4.1 Phase Timeline
| Field | Value |
|-------|-------|
| **id** | `panel-phase-timeline` |
| **role** | `utility` |
| **title** | Phase Timeline |
| **icon** | `layers` |
| **defaultWidth** | 280px |
| **defaultHeight** | 100% (anchored left) |
| **minWidth** | 220px · **maxWidth** 360px |
| **Anchor** | Left edge (replaces `.left-panel`) |
| **stateDeps** | `phases`, `progress` |
| **renderFn** | `renderPhases`, `renderProgress` |
| **removable** | false |
| **defaultVisible** | true |
| **Notes** | Left edge-anchored, horizontal resize only. Contains Intelligence Experience inline panel (`ixInlinePanel`) and Agent Chat panel sub-sections as collapsible sub-panels within this shell. |

---

### 4.2 Recon Pulse (Analytics Strip)
| Field | Value |
|-------|-------|
| **id** | `panel-recon-pulse` |
| **role** | `primary` |
| **title** | Recon Pulse |
| **icon** | `activity` |
| **defaultWidth** | 100% top strip |
| **defaultHeight** | 72px (collapsed) / 160px (expanded) |
| **Anchor** | Top of workspace body, below control bar |
| **stateDeps** | `stats`, `progress`, `eta` |
| **renderFn** | `renderStats`, `updateETA` |
| **removable** | false |
| **defaultVisible** | true |
| **Notes** | Houses the 5 stat cards + severity chart row. Not freely draggable — top-anchored strip. Can expand/collapse vertically. Cards are responsive: at <800px workspace they stack into 2-column grid. |

---

### 4.3 Severity Distribution
| Field | Value |
|-------|-------|
| **id** | `panel-severity-dist` |
| **role** | `secondary` |
| **title** | Severity Distribution |
| **icon** | `bar-chart` |
| **defaultWidth** | 260px |
| **defaultHeight** | 200px |
| **minWidth** | 180px · **maxWidth** 380px |
| **stateDeps** | `stats`, `findings` |
| **renderFn** | `renderStats` (severity section) |
| **removable** | true |
| **defaultVisible** | true |
| **Notes** | Severity filter strip is embedded. Clicking a severity chip emits `CC_CTX.emit('filter:severity', ...)`. |

---

### 4.4 Category Breakdown
| Field | Value |
|-------|-------|
| **id** | `panel-category-breakdown` |
| **role** | `secondary` |
| **title** | Category Breakdown |
| **icon** | `layers` |
| **defaultWidth** | 260px |
| **defaultHeight** | 200px |
| **minWidth** | 180px · **maxWidth** 380px |
| **stateDeps** | `stats`, `findings` |
| **renderFn** | `renderStats` (category section) |
| **removable** | true |
| **defaultVisible** | true |

---

### 4.5 Trend Graph
| Field | Value |
|-------|-------|
| **id** | `panel-trend-graph` |
| **role** | `primary` |
| **title** | Trend Graph |
| **icon** | `activity` |
| **defaultWidth** | 420px |
| **defaultHeight** | 240px |
| **minWidth** | 300px · **maxWidth** 900px |
| **stateDeps** | `stats`, `activity` |
| **renderFn** | (existing trend SVG renderer) |
| **removable** | true |
| **defaultVisible** | true |
| **Notes** | SVG canvas with crosshair/tooltip. The crosshair drag gesture MUST NOT be captured by the panel drag handle. See [Interaction Model §5.3 — Pointer Priority Rules]. Clicking a trend spike emits `CC_CTX.emit('filter:timeWindow', {start, end})`. |

---

### 4.6 Activity Feed
| Field | Value |
|-------|-------|
| **id** | `panel-activity-feed` |
| **role** | `primary` |
| **title** | Activity Feed |
| **icon** | `rss` |
| **defaultWidth** | 360px |
| **defaultHeight** | 320px |
| **minWidth** | 240px · **maxWidth** 700px |
| **stateDeps** | `activity`, `copilot` |
| **renderFn** | `renderActivity`, `_renderCopilotHelper` |
| **removable** | true |
| **defaultVisible** | true |
| **Notes** | Virtual scroll. Scroll container inside panel must not trigger panel drag. Receives `filter:timeWindow` and `filter:phase` from CC_CTX. Filtered view shows entry count badge. |

---

### 4.7 Findings Explorer
| Field | Value |
|-------|-------|
| **id** | `panel-findings-explorer` |
| **role** | `primary` |
| **title** | Findings Explorer |
| **icon** | `file-search` |
| **defaultWidth** | 380px |
| **defaultHeight** | 480px |
| **minWidth** | 280px · **maxWidth** 900px |
| **stateDeps** | `findings` |
| **renderFn** | `renderFindings` |
| **removable** | false |
| **defaultVisible** | true |
| **Notes** | Contains search + filter + sort + annotation filter + bulk bar + virtualized findings list. Emits `CC_CTX.emit('select:finding', {id, severity, phase, endpoint})`. Receives all filter slices from CC_CTX. This is the highest-priority primary panel in the default preset. |

---

### 4.8 Exploit Graph
| Field | Value |
|-------|-------|
| **id** | `panel-exploit-graph` |
| **role** | `primary` |
| **title** | Exploit Graph |
| **icon** | `swords` |
| **defaultWidth** | 480px |
| **defaultHeight** | 420px |
| **minWidth** | 320px · **maxWidth** unlimited |
| **stateDeps** | (direct — not dirty-gated) |
| **renderFn** | `_renderExploitGraphPanel` (direct call) |
| **removable** | true |
| **defaultVisible** | true |
| **Notes** | Force-directed or column layout toggle. The graph canvas captures all pointer events inside the content region. Panel drag ONLY activates from the panel title bar handle. Clicking a node emits `CC_CTX.emit('select:exploitNode', {nodeId, finding_ids[]})`. |

---

### 4.9 Console Feed
| Field | Value |
|-------|-------|
| **id** | `panel-console-feed` |
| **role** | `utility` |
| **title** | Console |
| **icon** | `terminal` |
| **defaultWidth** | 100% bottom strip |
| **defaultHeight** | 200px (default) / 40px (minimized) / 60% viewport (maximized) |
| **minHeight** | 40px · **maxHeight** 70% viewport |
| **Anchor** | Bottom edge (replaces `.console-panel`) |
| **stateDeps** | (event-driven, not dirty-gated) |
| **renderFn** | (existing console append logic) |
| **removable** | false |
| **defaultVisible** | true |
| **Notes** | This panel is a first-class system citizen. See full specification in [§8 — Console System]. It is not freely draggable. Bottom-anchored, vertical resize only. |

---

### 4.10 Quick Commands
| Field | Value |
|-------|-------|
| **id** | `panel-quick-commands` |
| **role** | `utility` |
| **title** | Quick Commands |
| **icon** | `zap` |
| **defaultWidth** | 240px |
| **defaultHeight** | 320px |
| **minWidth** | 180px · **maxWidth** 320px |
| **Anchor** | Right side-dock preferred (not strictly enforced) |
| **stateDeps** | none |
| **renderFn** | (tier1 buttons: Attack Graph, Heatmap, Targets, Gallery) |
| **removable** | true |
| **defaultVisible** | true |

---

### 4.11 MCP Activity
| Field | Value |
|-------|-------|
| **id** | `panel-mcp-activity` |
| **role** | `secondary` |
| **title** | MCP Server |
| **icon** | `server` |
| **defaultWidth** | 320px |
| **defaultHeight** | 280px |
| **minWidth** | 240px · **maxWidth** 500px |
| **stateDeps** | (direct — not dirty-gated) |
| **renderFn** | `_renderMcpPanel` (direct call) |
| **removable** | true |
| **defaultVisible** | false (shown on preset: `Exploit First`) |
| **Notes** | Currently invisible by default in the right panel. This panel makes it discoverable. |

---

### 4.12 Assessment Engine
| Field | Value |
|-------|-------|
| **id** | `panel-assessment-engine` |
| **role** | `primary` |
| **title** | Assessment Engine |
| **icon** | `microscope` |
| **defaultWidth** | 380px |
| **defaultHeight** | 360px |
| **minWidth** | 280px · **maxWidth** 700px |
| **stateDeps** | (direct — not dirty-gated) |
| **renderFn** | `_renderAssessmentPanel` (direct call) |
| **removable** | true |
| **defaultVisible** | false (shown on preset: `Findings First`) |

---

### 4.13 Atlas Intelligence
| Field | Value |
|-------|-------|
| **id** | `panel-atlas-intelligence` |
| **role** | `primary` |
| **title** | Atlas Intelligence |
| **icon** | `map` |
| **defaultWidth** | 360px |
| **defaultHeight** | 340px |
| **minWidth** | 260px · **maxWidth** 700px |
| **stateDeps** | `agent`, `reasoning`, `memory`, `llm` |
| **renderFn** | `_renderLlmIndicator`, `_renderReasoningPanel`, `_renderMemoryPanel`, `_renderAgentPanel` |
| **removable** | true |
| **defaultVisible** | true |
| **Notes** | Currently Atlas data is never consumed by the dashboard (known critical disconnection). This panel provides the mount point for that data when the disconnection is fixed. |

---

### 4.14 Technologies
| Field | Value |
|-------|-------|
| **id** | `panel-technologies` |
| **role** | `secondary` |
| **title** | Technologies |
| **icon** | `layers` |
| **defaultWidth** | 240px |
| **defaultHeight** | 200px |
| **minWidth** | 180px · **maxWidth** 400px |
| **stateDeps** | `findings` |
| **renderFn** | (tech extraction from findings, existing) |
| **removable** | true |
| **defaultVisible** | false |

---

### 4.15 Endpoints
| Field | Value |
|-------|-------|
| **id** | `panel-endpoints` |
| **role** | `secondary` |
| **title** | Endpoints |
| **icon** | `link` |
| **defaultWidth** | 280px |
| **defaultHeight** | 260px |
| **minWidth** | 200px · **maxWidth** 480px |
| **stateDeps** | `findings` |
| **renderFn** | (endpoint count from state, existing) |
| **removable** | true |
| **defaultVisible** | false |

---

### 4.16 Subdomains
| Field | Value |
|-------|-------|
| **id** | `panel-subdomains` |
| **role** | `secondary` |
| **title** | Subdomains |
| **icon** | `network` |
| **defaultWidth** | 280px |
| **defaultHeight** | 260px |
| **minWidth** | 200px · **maxWidth** 480px |
| **stateDeps** | `findings` |
| **renderFn** | (subdomain count from state, existing) |
| **removable** | true |
| **defaultVisible** | false |

---

### 4.17 Secrets
| Field | Value |
|-------|-------|
| **id** | `panel-secrets` |
| **role** | `secondary` |
| **title** | Secrets |
| **icon** | `lock` |
| **defaultWidth** | 280px |
| **defaultHeight** | 260px |
| **minWidth** | 200px · **maxWidth** 480px |
| **stateDeps** | `findings` |
| **renderFn** | (secrets count from state, existing) |
| **removable** | true |
| **defaultVisible** | false |

---

### 4.18 Screenshot Gallery
| Field | Value |
|-------|-------|
| **id** | `panel-screenshot-gallery` |
| **role** | `secondary` |
| **title** | Screenshots |
| **icon** | `camera` |
| **defaultWidth** | 400px |
| **defaultHeight** | 320px |
| **minWidth** | 280px · **maxWidth** 700px |
| **stateDeps** | `findings` |
| **renderFn** | (gallery tier1 button target, existing) |
| **removable** | true |
| **defaultVisible** | false |

---

### 4.19 Completion & Export
| Field | Value |
|-------|-------|
| **id** | `panel-completion` |
| **role** | `utility` |
| **title** | Completion |
| **icon** | `check-circle` |
| **defaultWidth** | 100% overlay |
| **defaultHeight** | auto |
| **Anchor** | Center overlay (shown only when scan completes) |
| **stateDeps** | `completion` |
| **renderFn** | `renderCompletion` |
| **removable** | false |
| **defaultVisible** | false (auto-shown on completion) |
| **Notes** | Not a free panel. This is an overlay that activates on scan completion. The panel registry entry provides the mount id and render binding. |

---

## 5. Interaction Model

### 5.1 Drag Architecture

**Rule:** The entire panel surface is NOT draggable. Only the panel title bar is.

```
┌──────────────────────────────────────────────────────┐
│ ░░░░ [DRAG HANDLE ZONE] Title   [role] [─] [□] [✕]  │  ← mousedown here = drag initiation
├──────────────────────────────────────────────────────┤
│                                                      │
│           PANEL CONTENT — pointer-events: all        │  ← mousedown here = NOT drag initiation
│                                                      │
├─────────────────────────────────────────────────────┤│
│                                        ╔═══╗         │  ← resize handle (bottom-right corner)
└─────────────────────────────────────────╚═══╝────────┘
```

**Drag initiation conditions:**
- `mousedown` target must be the `.panel-drag-handle` element (the title bar stripe, 28px tall)
- `mousedown` target must NOT be any button within the title bar (close, collapse, focus, menu)
- `mousedown` target must NOT be inside `.panel-content` (the inner content region)

**Drag implementation:**
```javascript
// Pseudo-code — actual implementation in CC_LAYOUT
shell.querySelector('.panel-drag-handle').addEventListener('mousedown', function(e) {
    if (e.target.closest('button, [data-nodrag]')) return;  // let buttons fire normally
    CC_LAYOUT.beginDrag(shell, e);
    e.preventDefault();
});
```

### 5.2 Resize Architecture

Each panel (where resizable) has explicit resize handles, not magic edge detection.

```
┌────────────────────────────────────────────────────────┐
│ Panel content                              [right-grip] │ ← 6px strip on right edge
│                                                        │
├──────────────────────────────────────────[corner-grip] ┤ ← 12×12px corner
│                       [bottom-grip]                    │ ← 6px strip on bottom edge
└────────────────────────────────────────────────────────┘
```

- `.panel-resize-right` — 6px wide strip, full height, right edge. Horizontal resize only.
- `.panel-resize-bottom` — 6px tall strip, full width, bottom edge. Vertical resize only.
- `.panel-resize-corner` — 12×12px, bottom-right. Freeform resize.
- Resize handles use `cursor: ew-resize`, `ns-resize`, `nwse-resize` respectively.
- Minimum size enforced per panel (`minWidth` / `minHeight` from registry).
- Maximum size enforced per panel (`maxWidth` / `maxHeight` from registry).
- Size is saved to persistence via `CC_PERSIST.save()` on mouseup.

**Utility-role panels** only get `.panel-resize-right` (horizontal only). No bottom or corner handle.

### 5.3 Pointer Priority Rules

This is the list of panels where inner content will fight the panel chrome for pointer events. Each case has an explicit resolution.

| Panel | Conflict | Resolution |
|-------|---------|------------|
| Trend Graph | SVG crosshair drag vs. panel drag | `pointer-events: none` on `.panel-drag-handle` while cursor is inside SVG canvas. SVG crosshair gets all events. Panel drag requires explicitly grabbing the title bar area outside the SVG. |
| Exploit Graph | Force-directed node drag vs. panel drag | Exploit graph canvas gets `pointer-events: all`. Panel drag handle is the title bar only. While a node drag is in progress (`CC_GRAPH.dragging === true`), panel drag is suppressed. |
| Activity Feed | Scroll wheel vs. panel resize | Scroll containers use `overscroll-behavior: contain`. Panel resize handles are outside the scroll container. No conflict. |
| Findings Explorer | Scroll + selection vs. panel drag | Same as Activity Feed. Virtualized list scroll container has `overscroll-behavior: contain`. |
| Console Feed | Text selection vs. vertical resize | Text selection fires only inside `.console-content`. The `.panel-resize-bottom` handle is a separate DOM node below it. No conflict. |

**Universal rule:** Any `mousedown` inside `.panel-content` must NOT propagate to the panel-level drag handler. This is enforced via:

```javascript
shell.querySelector('.panel-content').addEventListener('mousedown', function(e) {
    e.stopPropagation();  // do not let panel drag intercept
}, true);  // capture phase
```

### 5.4 Keyboard Navigation

| Key | Action | Scope |
|-----|--------|-------|
| `F` (while panel focused) | Toggle focus mode | Focused panel |
| `Esc` | Exit focus mode | Global |
| `Ctrl+Shift+P` | Open panel library | Global |
| `Ctrl+Shift+R` | Reset to default preset | Global |
| `Tab` | Cycle panel focus | Workspace |
| `Arrow keys` (while panel chrome focused) | Nudge panel position (4px steps) | Layout |

---

## 6. Analysis Context System

### 6.1 Design Objective

Replace ad-hoc one-off event callbacks with a **shared analysis context** — a single global object that all panels can read from and contribute to. This is the mechanism behind "linked analysis."

### 6.2 Canonical Filter Object (`CC_CTX.filter`)

```javascript
// This is the single source of truth for all cross-panel filtering.
// Read by any panel's render function to scope its data.
CC_CTX.filter = {
    // Time-based filtering
    timeWindow: null,           // null = all time | {start: ISO, end: ISO}
    
    // Entity-based filtering
    phase: null,                // null = all | phase_id string (e.g. "dns_enum")
    severity: null,             // null = all | "critical"|"high"|"medium"|"low"|"info"
    endpoint: null,             // null = all | URL string
    finding_id: null,           // null = none | finding UUID
    
    // Graph-based filtering
    exploit_node_id: null,      // null = none | exploit graph node id
    
    // Stack: multiple simultaneous filters
    stack: [],                  // array of filter objects, applied in order (AND logic)
    
    // Meta
    source_panel: null,         // which panel last emitted a filter change
    timestamp: null             // when filter last changed (for render throttle skip)
};
```

**Filter stacking rules:**
- Single filter: sets the top-level key directly (e.g. `CC_CTX.filter.severity = 'high'`)
- Stacked filter: adds to `stack[]` — all stack entries are AND'd
- Clearing: `CC_CTX.clearFilter(key)` removes a specific dimension
- `CC_CTX.clearAll()` resets everything to null

### 6.3 Subscription Model

Panels declare which filter slices they respond to in the registry (`filterSubscriptions[]`). The layout manager wires subscriptions automatically at mount time.

```javascript
// CC_PANELS registry entry example:
{
    id: 'panel-findings-explorer',
    filterSubscriptions: ['timeWindow', 'phase', 'severity', 'endpoint', 'exploit_node_id'],
    // ...
}

// CC_LAYOUT wires this at mount:
CC_CTX.subscribe('panel-findings-explorer', ['timeWindow', 'phase', 'severity'], function(filter) {
    markDirty('findings');  // trigger existing render cycle — no bypass
});
```

**Critical constraint:** Subscriptions MUST trigger the existing `markDirty()` system — they must never call render functions directly. This preserves the render throttle and prevents double-rendering.

### 6.4 Event Emission

Panels emit structured events, not ad-hoc callbacks.

```javascript
// Structured emission (all panels use this API):
CC_CTX.emit(eventType, payload, sourcePanel);

// Defined event types:
'filter:severity'       payload: { value: 'high' | null }
'filter:phase'          payload: { phase_id: string | null }
'filter:timeWindow'     payload: { start: ISO, end: ISO } | null
'filter:endpoint'       payload: { url: string | null }
'select:finding'        payload: { id: UUID, severity, phase, endpoint }
'select:exploitNode'    payload: { nodeId: string, finding_ids: UUID[] }
'console:timeSync'      payload: { timestamp: ISO }   // console drives global time cursor
'scan:phaseEnter'       payload: { phase_id: string } // auto-focus on active phase
'scan:spike'            payload: { metric: string, value: number, threshold: number }
```

### 6.5 Linked Analysis — User-Visible Behavior

| User Action | Emitted Event | Responding Panels |
|-------------|--------------|-------------------|
| Click phase in timeline | `filter:phase` | Activity Feed, Findings Explorer, Console Feed |
| Click severity chip | `filter:severity` | Findings Explorer, Category Breakdown, Trend Graph highlight |
| Drag crosshair on trend graph | `filter:timeWindow` | Activity Feed, Console Feed |
| Click finding in Findings Explorer | `select:finding` | Exploit Graph (highlights node), Activity Feed (scrolls to related entry) |
| Click exploit node | `select:exploitNode` | Findings Explorer (filters to node's findings), Activity Feed |
| Click console entry with timestamp | `console:timeSync` | Trend Graph (moves cursor to timestamp), Activity Feed (highlights matching window) |
| Active phase changes during scan | `scan:phaseEnter` | Phase Timeline (auto-scrolls to active), Activity Feed (scope marker), Console Feed (phase badge) |
| Finding count spikes | `scan:spike` | Findings Explorer (auto-expand if collapsed), Trend Graph (pulse animation) |

### 6.6 Linked vs. Unlinked Mode

Every non-utility panel has a **link toggle** in its panel chrome action bar:

- **Linked** (default): Panel responds to CC_CTX changes from other panels
- **Unlinked**: Panel ignores CC_CTX. Useful when comparing two time windows or holding a finding reference while looking at others.

The toggle is a chain-link icon in the panel header. When unlinked, a subtle amber border appears on the panel.

---

## 7. Persistence Architecture

### 7.1 The Four Dimensions

Layout persistence exists across four independent dimensions. Without a defined priority, they conflict.

| Dimension | Storage Key | Scope | Contents |
|-----------|-------------|-------|----------|
| **User Default** | `venator-layout-default` | Global (all targets) | Panel positions, sizes, visibility, role preferences |
| **Named Preset** | Built-in (code) | Global | One of 7 predefined layout snapshots |
| **Target Override** | `venator-layout-target-{hash}` | Per target URL | Layout snapshot for this specific target |
| **Session** | `sessionStorage['venator-layout-session']` | Current browser tab | Temporary adjustments made during active scan |

### 7.2 Priority Stack (Explicit Resolution Order)

```
Highest Priority
     │
     ▼
[4] Session          — temporary drag/resize during current scan
     │  (clears on tab close)
     ▼
[3] Target Override  — user explicitly saved layout for this target
     │  (survives refresh, scoped to target hash)
     ▼
[2] Named Preset     — user selected a named preset (not default)
     │  (overrides user default until changed)
     ▼
[1] User Default     — user's customized global default
     │  (initial state after first-time customization)
     ▼
[0] Hardcoded Default — CC_PANELS registry defaults
     (fallback when localStorage is empty or corrupted)

Lowest Priority
```

**Resolution function:**

```javascript
CC_PERSIST.hydrate = function(targetUrl) {
    const hash = _hashTarget(targetUrl);
    
    const session    = _readSession();
    const targetSave = localStorage.getItem('venator-layout-target-' + hash);
    const userDef    = localStorage.getItem('venator-layout-default');
    const preset     = localStorage.getItem('venator-active-preset');
    
    // Priority order: session > target > user default > named preset > hardcoded
    return session
        || (targetSave && JSON.parse(targetSave))
        || (userDef   && JSON.parse(userDef))
        || (preset    && CC_PRESETS[preset])
        || CC_PRESETS['default'];
};
```

### 7.3 Save Triggers

| Trigger | What is saved | Destination |
|---------|---------------|-------------|
| Panel drag released | Panel position | Session (immediate), User Default (debounced 2s) |
| Panel resize released | Panel size | Session (immediate), User Default (debounced 2s) |
| Panel closed/opened | Visibility | Session (immediate), User Default (debounced 2s) |
| User clicks "Save for this target" | Full current layout | Target Override |
| User clicks "Set as default" | Full current layout | User Default (immediate) |
| User selects a preset | Full preset layout | Active Preset key |
| User clicks "Reset" | Clears User Default + Session | (delete keys) |

### 7.4 Import / Export

- **Export**: `CC_PERSIST.export()` → downloads `venator-layout-{date}.json` — includes all 4 dimensions + filter state
- **Import**: `CC_PERSIST.import(file)` → validates schema version, merges into User Default slot
- **Schema version**: embedded as `schemaVersion: 2` in every export — incompatible versions show a migration warning

### 7.5 Corruption Handling

```javascript
CC_PERSIST.hydrate = function(targetUrl) {
    try {
        // ... priority resolution ...
    } catch(e) {
        console.warn('[CC_PERSIST] Layout state corrupt, falling back to default:', e);
        // Clear corrupt keys silently
        localStorage.removeItem('venator-layout-default');
        sessionStorage.removeItem('venator-layout-session');
        return CC_PRESETS['default'];
    }
};
```

---

## 8. Console System

The console is not a log panel. It is the **truth stream** of the scan.

### 8.1 Architectural Position

```
RunnerProcess
     │ stderr/stdout lines
     ▼
Backend WebSocket server
     │ {type: "console_line", timestamp, phase, level, text}
     ▼
recon-dashboard.js WS handler
     │
     ▼
CC_CONSOLE  ←──── ALL raw scan output arrives here first
     │
     ├──► CC_CTX.emit('console:timeSync', ...)  ← drives time cursor
     ├──► Phase detection → CC_CTX.emit('scan:phaseEnter', ...)
     ├──► Spike detection → CC_CTX.emit('scan:spike', ...)
     └──► Console panel DOM append (existing consoleFeed logic)
```

### 8.2 Console as Time Backbone

Every console line has a timestamp. This makes the console the only panel that can anchor all other panels to a specific moment in time.

- Hovering over a console line shows a "Sync" icon
- Clicking the timestamp emits `CC_CTX.emit('console:timeSync', {timestamp})`
- This moves the Trend Graph cursor to that timestamp
- Activity Feed highlights entries within ±30s of that timestamp
- Phase Timeline highlights the phase active at that timestamp

### 8.3 Console as Truth Stream

The console does not filter. It cannot be scoped. It is the ground truth.

- Other panels receive filtered views (via CC_CTX)
- The console always shows everything — it is the escape hatch when a filter produces empty results
- A subtle "truth baseline" indicator appears in other panels when a filter is active: "Showing 12 of 847 findings — [clear filter]"

### 8.4 Console Panel Behavior

| State | Height | Behavior |
|-------|--------|----------|
| Minimized | 40px | Shows last line + phase badge. Click to expand. |
| Default | 200px | Normal scrollback. Auto-scroll on new lines unless user has scrolled up. |
| Expanded | 60% viewport | Full scrollback with search. |
| Maximized | 100% workspace | Occupies entire workspace body. Other panels dim to 0 opacity. |

- **Auto-scroll**: active when scroll position is within 40px of bottom. Pauses on user scroll-up. Resumes on scroll-to-bottom.
- **Console search**: `Ctrl+F` within console panel opens inline search bar. Filters console lines (does NOT affect CC_CTX).
- **Phase stamps**: Phase transitions emit a visual divider line in the console feed showing phase name + timestamp.
- **Level colors**: `error` → critical red · `warn` → amber · `info` → default · `debug` → muted (collapsed by default with toggle)
- **Auto-scope**: when Focus Mode is active on another panel, console automatically scopes to lines matching that panel's active CC_CTX filter (visual scope, not data destruction).

### 8.5 Console Layout Properties

- Bottom-anchored. Not freely draggable.
- Vertical resize only (resize handle on top edge, not bottom).
- Min height: 40px (single-line minimized state).
- Max height: 70% viewport.
- The existing `conResizeHandle` logic in `recon-dashboard.js` is preserved in Stage 1-2 and superseded in Stage 3 by the workspace panel system.

---

## 9. Focus Mode Bias System

### 9.1 Concept

Focus mode is the mechanism that turns the dashboard from "a collection of panels" into "an analysis surface centered on one thing."

It is not fullscreen. It is bias. The focused panel expands; others dim — but remain visible.

### 9.2 Behavior Specification

```
Normal state:
┌──────┐ ┌──────┐ ┌──────┐
│Panel │ │Panel │ │Panel │   All panels at opacity: 1.0, normal size
└──────┘ └──────┘ └──────┘

Focus mode (middle panel focused):
┌──────┐ ╔══════════════╗ ┌──────┐
│      │ ║              ║ │      │
│Panel │ ║  FOCUSED     ║ │Panel │   Focused: expanded, bright, z-index raised
│ dim  │ ║  PANEL       ║ │ dim  │   Others: opacity 0.45, non-interactive chrome
│      │ ║              ║ │      │
└──────┘ ╚══════════════╝ └──────┘
```

### 9.3 CSS Implementation

```css
/* When workspace is in focus mode */
.workspace.focus-active .panel-shell {
    opacity: 0.45;
    pointer-events: none;     /* chrome non-interactive */
    transition: opacity 180ms ease;
}

.workspace.focus-active .panel-shell.panel-focused {
    opacity: 1.0;
    pointer-events: all;
    z-index: 100;
    box-shadow: 0 0 0 1px var(--accent-primary), 0 8px 32px rgba(0,0,0,0.6);
    transition: opacity 180ms ease, box-shadow 180ms ease;
}

/* Utility panels (console, phase timeline) never dim */
.workspace.focus-active .panel-shell[data-role="utility"] {
    opacity: 1.0;
    pointer-events: all;
}
```

### 9.4 Linked Analysis in Focus Mode

When a primary panel enters focus mode, its linked highlights intensify:

- Exploit Graph: node halos brighten, unrelated nodes fade to 15% opacity
- Trend Graph: the time cursor becomes a solid vertical line (vs. dashed in normal mode)
- Activity Feed: matching entries get a left-side bright accent bar; non-matching entries collapse to 1-line previews

### 9.5 Console Auto-Scope in Focus Mode

When a panel is focused and a CC_CTX filter is active, the console:

1. Dims non-matching lines to 30% opacity
2. Shows a "Scoped to: [filter description]" banner at top of console
3. Maintains full scrollback (no lines removed — only visually dimmed)
4. Provides a "Exit scope" button to restore full view without exiting focus mode

### 9.6 Focus Mode Activation

| Method | Action |
|--------|--------|
| Click `[□]` button in panel chrome | Enter focus mode for that panel |
| Press `F` while panel chrome is keyboard-focused | Enter focus mode |
| Double-click panel title bar | Enter focus mode |
| Press `Esc` | Exit focus mode (global) |
| Click outside focused panel | Exit focus mode |

---

## 10. Layout Intelligence System

This is smart defaults — not AI. It observes usage patterns and scan state to make better decisions automatically.

### 10.1 Snap Groups

Related panels snap near each other during drag. Snap groups are defined in the registry.

```javascript
CC_LAYOUT.SNAP_GROUPS = {
    'findings-cluster':  ['panel-findings-explorer', 'panel-severity-dist', 'panel-assessment-engine'],
    'exploit-cluster':   ['panel-exploit-graph', 'panel-mcp-activity'],
    'intel-cluster':     ['panel-atlas-intelligence', 'panel-technologies', 'panel-endpoints'],
    'timeline-cluster':  ['panel-activity-feed', 'panel-trend-graph'],
};
```

When a panel from a snap group is dragged near another member of the same group (within 40px), a ghost guide appears showing where it would snap. Release to snap.

### 10.2 Usage-Based Layout Suggestions

Track which panels a user spends time focused on (time-in-focus, clicks, scroll events). After 3 scans, offer a "Smart Preset" that reflects actual usage patterns.

```javascript
// Persisted usage vector (not sent to any server)
CC_LAYOUT._usageVector = localStorage.getItem('venator-panel-usage') || {};
// Shape: { 'panel-findings-explorer': { focusTime: 1240, clicks: 87, scrolls: 234 } }
```

The suggestion is non-intrusive: a "Your Usage" preset option appears in the preset selector after the third scan.

### 10.3 Auto-Expand on Event Spike

When `CC_CTX.emit('scan:spike', {metric, value, threshold})` fires:

```javascript
CC_LAYOUT.onSpike = function(metric, value) {
    const spikeMap = {
        'findings_rate':   'panel-findings-explorer',
        'exploit_nodes':   'panel-exploit-graph',
        'error_rate':      'panel-console-feed',
        'subdomain_count': 'panel-subdomains'
    };
    const target = spikeMap[metric];
    if (!target) return;
    
    const panel = CC_LAYOUT.getPanel(target);
    if (panel && panel.state === 'collapsed') {
        CC_LAYOUT.expandPanel(target, { reason: 'spike', metric, value });
        // Show a "Spike detected" badge on the panel for 8s
        panel.shell.classList.add('spike-alert');
        setTimeout(() => panel.shell.classList.remove('spike-alert'), 8000);
    }
};
```

### 10.4 Phase-Driven Layout Hints

Certain phases naturally prioritize certain panels. During an active scan, the phase timeline emits `scan:phaseEnter` which triggers layout hints:

| Phase Type | Hint |
|------------|------|
| `dns_*` | Subdomains panel gets a subtle pulse animation |
| `endpoint_*` | Endpoints panel gets pulse animation |
| `exploit_*` | Exploit Graph panel gets focus suggestion badge |
| `secret_*` | Secrets panel gets pulse animation |

Hints are visual only (pulse, badge). They do not auto-focus or auto-expand unless the user has enabled "Auto-Focus Suggestions" in settings.

---

## 11. Visual Specification

This section is **actionable only**. No atmospheric descriptions.

### 11.1 Typography & Density Targets

| Element | Current | Target |
|---------|---------|--------|
| Panel title | 13px / 500 | 11px / 600 (uppercase tracking: 0.04em) |
| Body text | 13px | 12px |
| Stat card label | 11px | 10px / uppercase |
| Stat card value | 22px | 20px |
| Finding row height | ~48px | 36px (tight) / 28px (compact mode) |
| Activity row height | ~40px | 30px |
| Console line height | 18px | 16px |
| Phase list item | ~44px | 32px |

### 11.2 Panel Chrome Specification

```
Height:   28px (down from implicit ~36px current panel headers)
Padding:  0 8px
Layout:   flex, items centered, gap: 4px

Left:     [drag-grip icon 10px] [panel icon 14px] [panel title text]
Center:   [role chip] [linked/unlinked icon] [filter-active badge (shows count)]
Right:    [minimize] [focus] [menu ▾]    all buttons: 20×20px tap target
```

**Role chip styles:**

```css
.panel-role-chip {
    font-size: 9px;
    font-weight: 700;
    letter-spacing: 0.06em;
    text-transform: uppercase;
    padding: 1px 5px;
    border-radius: 3px;
}
.panel-role-chip.primary  { background: rgba(99, 102, 241, 0.15); color: #818cf8; }
.panel-role-chip.secondary{ background: rgba(20, 184, 166, 0.12); color: #5eead4; }
.panel-role-chip.utility  { background: rgba(100, 116, 139, 0.15); color: #94a3b8; }
```

### 11.3 Status Chips

Replace emoji status labels with structured chips throughout:

```html
<!-- Before: "🔴 Critical" text in findings rows -->
<!-- After: -->
<span class="sev-chip sev-critical">CRIT</span>
<span class="sev-chip sev-high">HIGH</span>
<span class="sev-chip sev-medium">MED</span>
<span class="sev-chip sev-low">LOW</span>
<span class="sev-chip sev-info">INFO</span>
```

```css
.sev-chip {
    display: inline-flex;
    align-items: center;
    height: 16px;
    padding: 0 5px;
    border-radius: 3px;
    font-size: 9px;
    font-weight: 700;
    letter-spacing: 0.06em;
    white-space: nowrap;
}
.sev-chip.sev-critical { background: rgba(239,68,68,0.15); color: #f87171; border: 1px solid rgba(239,68,68,0.3); }
.sev-chip.sev-high     { background: rgba(249,115,22,0.12); color: #fb923c; border: 1px solid rgba(249,115,22,0.25); }
.sev-chip.sev-medium   { background: rgba(234,179,8,0.12);  color: #fbbf24; border: 1px solid rgba(234,179,8,0.25); }
.sev-chip.sev-low      { background: rgba(59,130,246,0.12); color: #60a5fa; border: 1px solid rgba(59,130,246,0.25); }
.sev-chip.sev-info     { background: rgba(100,116,139,0.12);color: #94a3b8; border: 1px solid rgba(100,116,139,0.2); }
```

### 11.4 Header Density

Current header height: ~52px. Target: 40px.

Changes:
- Logo: 14px → 13px, tracking +0.08em
- Target URL display: truncate to 300px max-width, ellipsis
- Infra indicators: reduce internal padding from ~8px to 5px
- Timer font: 13px → 12px
- WS status: combine dot + text into one 28px pill (current takes ~90px)
- Session badge: icon only in collapsed state (12px icon, expands on hover to show ID)

### 11.5 Phase Timeline Rail

```
Current:  icon + full phase name + status + progress bar = ~44px per item
Target:   icon + abbreviated name + status dot = 28px per item (compact)
          Hover: expand to full name (tooltip or inline expand)
          Active phase: 36px with inline progress bar (exception to compact rule)
```

### 11.6 Stat Cards

```
Current:  large glass card, 22px value, 11px label, substantial padding
Target:   tighter card, 20px value, 10px label, 8px padding
          Delta indicator: +12 ↑ in 10px text, colored (green/red)
          Trend sparkline: 32×16px inline SVG replacing the full severity chart
          (full severity chart moved to panel-severity-dist)
```

### 11.7 Depth Separation

Use border + shadow contrast, not blur, for depth:

```css
/* Panel shells — raised surface */
.panel-shell {
    background: var(--surface-raised);          /* #1a1f2e */
    border: 1px solid rgba(255,255,255,0.06);
    box-shadow: 0 2px 8px rgba(0,0,0,0.3);
}

/* Panel content inner — recessed */
.panel-content {
    background: var(--surface-base);            /* #161b27 */
    border-top: 1px solid rgba(0,0,0,0.25);
}

/* Workspace background — deepest layer */
.workspace-grid {
    background: var(--surface-deep);            /* #0f1319 */
}
```

---

## 12. Workspace Presets

All presets are JSON snapshots consumed by `CC_LAYOUT.applyPreset(name)`.

### Preset 1: Default
Best balance of all panels for a standard pentest session.

```
┌──────────────┬────────────────────────────────────────┬──────────────┐
│ Phase        │ [Recon Pulse Strip — full width]       │ Findings     │
│ Timeline     ├─────────────────────┬──────────────────│ Explorer     │
│ (left dock)  │ Activity Feed       │ Trend Graph      │              │
│              │                     │                  ├──────────────┤
│              ├─────────────────────┴──────────────────┤ Atlas        │
│              │ [Console — bottom dock]                │ Intelligence  │
└──────────────┴────────────────────────────────────────┴──────────────┘
```

### Preset 2: Findings First
Maximize Findings Explorer. For triage-heavy sessions.

```
┌──────────────┬──────────────────────────────────────────────────────┐
│ Phase        │ Findings Explorer (wide, full height minus pulse)    │
│ Timeline     ├──────────────────────────────────────────────────────┤
│ (left dock)  │ Severity Dist │ Category Breakdown │ Assessment Engine│
│              ├──────────────────────────────────────────────────────┤
│              │ [Console — bottom dock]                              │
└──────────────┴──────────────────────────────────────────────────────┘
```

### Preset 3: Exploit First
Exploit Graph dominates. For post-scan exploitation sessions.

```
┌──────────────┬───────────────────────────────────┬──────────────────┐
│ Phase        │ Exploit Graph (large)              │ Findings Explorer│
│ Timeline     │                                   │ (narrow)         │
│ (left dock)  ├───────────────────────────────────┤                  │
│              │ MCP Activity │ Quick Commands      │                  │
│              ├───────────────────────────────────┴──────────────────┤
│              │ [Console — bottom dock]                              │
└──────────────┴──────────────────────────────────────────────────────┘
```

### Preset 4: Console First
Console maximized. For real-time command + output monitoring.

```
┌──────────────┬─────────────────────┬──────────────────────────────┐
│ Phase        │ Activity Feed       │ Findings Explorer            │
│ Timeline     │ (compact)           │ (compact)                    │
│ (left dock)  ├─────────────────────┴──────────────────────────────┤
│              │                                                    │
│              │  Console (large — 55% height)                      │
│              │                                                    │
└──────────────┴────────────────────────────────────────────────────┘
```

### Preset 5: Executive Summary
High-level stats only. For screenshot / report generation.

```
┌───────────────────────────────────────────────────────────────────┐
│ [Recon Pulse Strip + Severity Distribution + Category Breakdown]  │
├────────────────────────────────────┬──────────────────────────────┤
│ Findings Explorer (critical/high   │ Trend Graph                  │
│ filter pre-applied)                │                              │
├────────────────────────────────────┴──────────────────────────────┤
│ Completion & Export                                               │
└───────────────────────────────────────────────────────────────────┘
```
*(Phase timeline hidden in this preset. Console minimized to 40px.)*

### Preset 6: Compact Laptop
For 13" / 1366×768 screens. Minimal chrome, maximum content density.

```
┌──────┬───────────────────────────┬───────────────────────────────┐
│Phase │ Findings Explorer          │ Activity Feed                 │
│(220px│ (compact rows, 28px)       │ (compact rows)                │
│icon- ├────────────────────────────┴───────────────────────────────┤
│only) │ [Console — 40px minimized — auto-expand on error]          │
└──────┴────────────────────────────────────────────────────────────┘
```
*(Phase timeline is icon-rail only — 48px wide, labels on hover. Recon Pulse collapsed to 40px single-row strip.)*

### Preset 7: Wallboard
For monitoring screens / NOC. Auto-rotates panel focus every 30s.

```
┌─────────────────────────┬────────────────────────────────────────┐
│ Trend Graph             │ Findings Explorer                      │
│ (fullscreen-width)      │ (auto-sorted by recency)               │
├─────────────────────────┤                                        │
│ Phase Timeline          │                                        │
│ (horizontal rail mode)  ├────────────────────────────────────────┤
│                         │ Exploit Graph                          │
├─────────────────────────┤                                        │
│ Recon Pulse             │                                        │
└─────────────────────────┴────────────────────────────────────────┘
```
*(No console shown. Agent Chat hidden. Auto-rotate cycle: Findings → Exploit Graph → Trend → Findings…)*

---

## 13. Widget Registry Schema

The definitive JS object structure for `CC_PANELS`. Each entry is a panel definition.

```javascript
const CC_PANELS = {

    'panel-findings-explorer': {
        // Identity
        id:           'panel-findings-explorer',
        title:        'Findings Explorer',
        icon:         'file-search',
        role:         'primary',              // 'primary' | 'secondary' | 'utility'

        // Default geometry
        defaultWidth:  380,
        defaultHeight: 480,
        minWidth:      280,
        maxWidth:      900,
        minHeight:     200,
        maxHeight:     null,                  // null = unlimited

        // Default position (grid-based, not pixel)
        defaultPosition: { col: 3, row: 1 }, // grid column/row in default preset

        // Anchoring (overrides drag behavior for utility panels)
        anchor:        null,                  // null | 'left' | 'right' | 'top' | 'bottom'
        anchorSize:    null,                  // px value if anchored

        // State + render wiring
        stateDeps:     ['findings'],          // which _dirty keys trigger this panel
        filterSubscriptions: ['timeWindow', 'phase', 'severity', 'endpoint', 'exploit_node_id'],
        renderFn:      'renderFindings',      // string name of function in JS scope
        directRender:  false,                 // true = not dirty-gated (MCP, Assessment, ExploitGraph)

        // Interaction
        draggable:     true,
        resizable:     true,                  // both axes
        resizeAxes:    ['x', 'y'],            // 'x' | 'y' | both
        focusable:     true,                  // participates in focus mode as focused panel
        linked:        true,                  // default linked state (user can toggle)

        // Visibility
        removable:     false,
        defaultVisible: true,
        panelLibrary:  true,                  // appears in panel library for user to add/remove

        // Snap group
        snapGroup:    'findings-cluster',

        // Filter emissions (which CC_CTX events this panel emits)
        emits:        ['select:finding'],

        // Auto-expand trigger
        spikeMetric:  'findings_rate',

        // Preset slot overrides (panel-specific layout per preset)
        presetSlots: {
            'default':           { col: 3, row: 1, width: 380, height: 480 },
            'findings-first':    { col: 2, row: 1, width: 700, height: 600 },
            'exploit-first':     { col: 3, row: 1, width: 320, height: 480 },
            'console-first':     { col: 3, row: 1, width: 340, height: 280 },
            'executive-summary': { col: 1, row: 2, width: 600, height: 400 },
            'compact-laptop':    { col: 2, row: 1, width: 480, height: 380 },
            'wallboard':         { col: 2, row: 1, width: 560, height: 500 }
        }
    },

    // ... (each of the 19 panels has an entry following this schema)

};
```

**Required fields:** `id`, `title`, `icon`, `role`, `defaultWidth`, `defaultHeight`, `stateDeps`, `renderFn`, `removable`, `defaultVisible`

**Optional fields** (default values assumed if absent): `minWidth` (120), `maxWidth` (null), `anchor` (null), `filterSubscriptions` ([]), `draggable` (true), `resizable` (true), `focusable` (role === 'primary'), `linked` (true), `snapGroup` (null), `emits` ([]), `spikeMetric` (null)

---

## 14. Rollout Plan — 6 Stages

### Stage 1 — Build the Workspace Layer (no user-visible change)
**Duration estimate:** First complete stage before any UI changes.

**Deliverables:**
- `CC_PANELS` registry object added to `recon-dashboard.js` (alongside `CC_ICONS`)
- `CC_CTX` analysis context object (init, emit, subscribe, clearFilter functions)
- `CC_PERSIST` persistence module (hydrate, save, export, import functions)
- `CC_LAYOUT` stub (mount, applyLayout, getPanel — no DOM changes yet)
- Unit-testable: all three modules can be exercised without a browser

**Validation:** Run existing dashboard. Zero visual or behavioral change.

---

### Stage 2 — Wrap Fixed Regions in Panel Shells

**Deliverables:**
- Replace `.main` div's fixed 3-column structure with `.workspace-grid` container in `recon-dashboard-body.html`
- All existing panel div ids **unchanged** — wrapped in new `.panel-shell` div
- Panel chrome added (drag handle, title, role chip, minimize/focus/menu buttons)
- Panel CSS added to `recon-dashboard.css` (`.panel-shell`, `.panel-drag-handle`, `.panel-content`, `.panel-resize-*`)
- Left panel → becomes `panel-phase-timeline` (anchored)
- Right panel → becomes `panel-findings-explorer` + stacked secondary panels
- Center panels → become individually wrapped panels
- Console → becomes `panel-console-feed` (anchored bottom)
- `initSplitters()` disabled (old left/right splitter replaced by panel resize handles)
- `conResizeHandle` disabled (replaced by panel resize handle on console top edge)

**Validation:** All existing render functions fire correctly. All DOM ids resolve. WS state_snapshot restores correctly. Layout matches "Default" preset visually.

---

### Stage 3 — Persistence and Presets

**Deliverables:**
- `CC_PERSIST.hydrate()` wired at page load
- Panel drag + resize save to session immediately, User Default debounced 2s
- 7 named presets fully defined as JSON in `CC_PRESETS`
- Preset selector UI (replaces nothing — added to header right or workspace toolbar)
- "Save for this target" button in workspace toolbar
- "Reset to default" confirmation dialog
- Import / export JSON functionality
- Old `cc_leftPanelWidth` / `cc_rightPanelWidth` localStorage keys migrated to new schema on first load, then deleted

**Validation:** Drag panel, refresh page — position restored. Switch preset — layout changes. Target override persists across sessions.

---

### Stage 4 — Analysis Context Wiring

**Deliverables:**
- `CC_CTX.emit()` calls added at all linked analysis trigger points:
  - Phase timeline click → `filter:phase`
  - Severity chip click → `filter:severity`
  - Trend graph crosshair release → `filter:timeWindow`
  - Finding row click → `select:finding`
  - Exploit node click → `select:exploitNode`
  - Console line timestamp click → `console:timeSync`
  - Phase transition during scan → `scan:phaseEnter`
  - Spike detection in WS event_batch handler → `scan:spike`
- Panel subscriptions wired by `CC_LAYOUT.mount()` via registry `filterSubscriptions`
- All subscriptions call `markDirty(key)` — no direct render calls from subscriptions
- Linked/unlinked toggle working per panel
- Filter-active badge shows count in panel chrome

**Validation:** Click a phase → Activity Feed and Console scope to that phase. Click a finding → Exploit Graph highlights. Trend crosshair drag → Activity Feed filters to time window.

---

### Stage 5 — Focus Mode + Layout Intelligence

**Deliverables:**
- Focus mode CSS (`.workspace.focus-active`, `.panel-focused`, dim transitions)
- Focus mode activation: `[□]` button, `F` key, double-click title bar
- `Esc` exits focus mode
- Console auto-scope in focus mode (visual dim of non-matching lines)
- Linked highlight intensification in focus mode (per panel type)
- `CC_LAYOUT.SNAP_GROUPS` defined and snapping behavior implemented
- Usage vector tracking (`venator-panel-usage` localStorage)
- "Your Usage" preset appears after 3 scans
- Auto-expand on spike (`CC_LAYOUT.onSpike`)
- Phase-driven layout hints (pulse animation on relevant panels)

**Validation:** Enter focus mode on Findings Explorer → Exploit Graph dims, linked highlights intensify. Spike in findings rate → collapsed Findings Explorer auto-expands with badge.

---

### Stage 6 — Visual Density + Polish

**Deliverables:**
- Header density reduction (40px height, all changes from §11.4)
- Status chips replacing emoji labels throughout (§11.3)
- Typography density targets applied (§11.1)
- Phase timeline compact rail (28px items, icon-only at 220px width, §11.5)
- Stat card tightening (§11.6)
- Depth separation CSS variables finalized (§11.7)
- Compact mode (28px finding rows) added as global density toggle in settings
- Wallboard preset auto-rotate timer implemented
- Keyboard navigation (Tab cycling, `F` focus, arrow nudge) implemented
- All ~118 remaining inline emoji in template literals replaced with `ccIcon()` calls

**Validation:** Full visual regression pass across all 7 presets. Mobile breakpoint (768px) tested — all panels stack correctly. Performance: `renderAll()` timing unchanged (workspace layer adds <2ms overhead).

---

## 15. Engineering Rules (Hard Constraints)

These are the "stop and re-plan" rules. No exceptions during Stages 1-4.

| Rule | Enforcement |
|------|-------------|
| **Never call a render function from a CC_CTX subscription.** Always call `markDirty()`. | Code review gate |
| **Never remove an existing DOM id.** Panel shells are added around them, not replacing them. | Automated id audit script (`_audit_dom_ids.py`) |
| **Never add a subscription without a corresponding `filterSubscriptions` entry in CC_PANELS.** Ad-hoc subscriptions are forbidden. | Registry-only subscription wiring |
| **Never modify `renderAll()` or any individual render function during Stages 1-4.** Interior render changes are Stage 6+ territory. | Change freeze on `renderAll`, `renderFindings`, `renderActivity`, `_renderExploitGraphPanel`, `_renderMcpPanel`, `_renderAssessmentPanel` |
| **Never let panel drag capture pointer events inside `.panel-content`.** The `stopPropagation()` capture handler is mandatory on every panel content region. | CSS + JS audit per panel |
| **Never use `innerHTML` replacement on a container with an existing DOM id.** Use `appendChild`, `insertBefore`, or class-based visibility. | Diff audit on each stage |
| **The panel registry is the single source of truth for panel configuration.** No ad-hoc panel sizing, no hardcoded panel widths in JS outside the registry. | Grep audit: no hardcoded pixel widths in layout functions |
| **"Let's just rewrite this one panel" is forbidden.** | Human enforcement — call this out in every review |

---

*End of specification. Version 1.0 — April 21, 2026.*
