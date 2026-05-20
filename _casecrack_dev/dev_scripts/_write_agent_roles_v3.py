"""Regenerate agent_roles.py with all 5 emergent gaps (v3)."""
import pathlib

TARGET = pathlib.Path(r"c:\Users\ya754\CaseCrack v1.0\CaseCrack\tools\burp_enterprise\agent_roles.py")

CONTENT = '''\
"""Explicit Multi-Agent Role System -- parallel reasoning, specialization, cleaner scaling.

Architecture (Cross-Examination v3 -- 5 Emergent Gaps closed):

  +------------------------------------------------------------------+
  | AgentCoordinator (orchestrates all specialist agents)             |
  |  +-- ReconAgent    -- discovery: subdomains, ports, tech, crawl   |
  |  +-- ExploitAgent  -- validation: PoC, exploit chains, proof      |
  |  +-- StrategyAgent -- prioritization: phase/budget/mode choice    |
  |  +-- MemoryAgent   -- learning: cross-scan patterns, recall       |
  |  +-- DefenseAgent  -- evasion: WAF bypass, stealth, rate-limit    |
  |                                                                    |
  |  Communication:                                                    |
  |  AgentMailbox (typed messages) + SharedContext (shared state)      |
  |  AgentMessage (structured)     + EventBus (real-time events)      |
  |                                                                    |
  |  v2 Foundation (12 gaps):                                          |
  |  GAPs I-XII: Spawn-vs-Continue, Terminal Status, Permission       |
  |  Cascade, Multi-Point Abort, ProgressTracker, Cleanup,            |
  |  Auto-Resume, Cost/Usage, Token Budget, Peer-to-Peer,             |
  |  Lifecycle Hooks, Dispatch History                                 |
  |                                                                    |
  |  v3 Emergent Intelligence (5 gaps):                                |
  |  - E-GAP 1: Agent Identity Evolution (learning profiles)          |
  |  - E-GAP 2: Structured Conflict Resolution Engine                 |
  |  - E-GAP 3: Pre-Decision Memory Injection                         |
  |  - E-GAP 4: Simulation / Prediction Layer                         |
  |  - E-GAP 5: Emergent Multi-Step Strategy Formation                |
  +------------------------------------------------------------------+
"""

from __future__ import annotations

import enum
import logging
import math
import threading
import time
import uuid
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Callable

logger = logging.getLogger(__name__)

# ===================================================================
# CONSTANTS
# ===================================================================

AGENT_COLORS: dict[str, str] = {
    "recon": "cyan",
    "exploit": "red",
    "strategy": "green",
    "memory": "purple",
    "defense": "orange",
}

TASK_ID_PREFIXES: dict[str, str] = {
    "recon": "r-",
    "exploit": "x-",
    "strategy": "s-",
    "memory": "m-",
    "defense": "d-",
}

_TERMINAL_STATUSES = frozenset({"completed", "failed", "aborted", "timeout", "killed"})


# ===================================================================
# ENUMS
# ===================================================================


class AgentRoleType(enum.Enum):
    RECON = "recon"
    EXPLOIT = "exploit"
    STRATEGY = "strategy"
    MEMORY = "memory"
    DEFENSE = "defense"


class AgentState(enum.Enum):
    IDLE = "idle"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    RETIRED = "retired"


class MessageType(enum.Enum):
    TASK_ASSIGN = "task_assign"
    TASK_RESULT = "task_result"
    TASK_FAILED = "task_failed"
    INTEL_SHARE = "intel_share"
    CONSTRAINT_ALERT = "constraint_alert"
    STRATEGY_UPDATE = "strategy_update"
    HEALTH_CHECK = "health_check"
    HEALTH_RESPONSE = "health_response"
    BROADCAST = "broadcast"
    OPINION_SUBMIT = "opinion_submit"
    DISSENT = "dissent"
    CHALLENGE = "challenge"
    OVERRIDE_REQUEST = "override_request"
    MEMORY_INJECT = "memory_inject"
    PLAN_PROPOSAL = "plan_proposal"
    PLAN_VOTE = "plan_vote"
    EMERGENT_SIGNAL = "emergent_signal"
    PEER_REQUEST = "peer_request"
    PEER_RESPONSE = "peer_response"
    # E-GAP 2: Conflict resolution messages
    CONFLICT_POSITION = "conflict_position"
    CONFLICT_VERDICT = "conflict_verdict"
    # E-GAP 3: Pre-decision memory recall
    MEMORY_RECALL_REQUEST = "memory_recall_request"
    MEMORY_RECALL_RESPONSE = "memory_recall_response"
    # E-GAP 4: Simulation
    SIMULATION_REQUEST = "simulation_request"
    SIMULATION_RESULT = "simulation_result"
    # E-GAP 5: Strategy arc
    STRATEGY_ARC_UPDATE = "strategy_arc_update"
    PHASE_TRANSITION = "phase_transition"


class ExecutionMode(enum.Enum):
    PARALLEL = "parallel"
    SEQUENTIAL = "sequential"
    ADVISORY = "advisory"


class PermissionMode(enum.Enum):
    RESTRICTED = 0
    DEFAULT = 1
    ACCEPT_RESULTS = 2
    AUTONOMOUS = 3
    BYPASS = 4


class AbortReason(enum.Enum):
    USER_CANCEL = "user_cancel"
    TIMEOUT = "timeout"
    MAX_TURNS = "max_turns"
    COORDINATOR_KILL = "coordinator_kill"
    BUDGET_EXHAUSTED = "budget_exhausted"
    PARENT_ABORT = "parent_abort"
    DIMINISHING_RETURNS = "diminishing_returns"


class HookPhase(enum.Enum):
    PRE_EXECUTE = "pre_execute"
    POST_EXECUTE = "post_execute"
    ON_ABORT = "on_abort"
    ON_IDLE = "on_idle"
    ON_CLEANUP = "on_cleanup"
    ON_RESUME = "on_resume"


class ConflictResolutionMethod(enum.Enum):
    """E-GAP 2: How a conflict was resolved."""
    WEIGHTED_VOTE = "weighted_vote"
    EVIDENCE_STRENGTH = "evidence_strength"
    CONFIDENCE_SPREAD = "confidence_spread"
    ESCALATION = "escalation"
    UNANIMOUS = "unanimous"


class StrategyArcPhase(enum.Enum):
    """E-GAP 5: Phases within a multi-step strategic arc."""
    RECONNAISSANCE = "reconnaissance"
    ANALYSIS = "analysis"
    EXPLOITATION = "exploitation"
    VERIFICATION = "verification"
    CONSOLIDATION = "consolidation"
    PIVOT = "pivot"


# ===================================================================
# SENTINEL EXCEPTIONS
# ===================================================================


class _AgentAborted(Exception):
    def __init__(self, message: str = "", reason: AbortReason = AbortReason.USER_CANCEL):
        super().__init__(message)
        self.reason = reason


class _AgentTimeout(Exception):
    pass


class _AgentBudgetExhausted(Exception):
    pass


# ===================================================================
# HELPERS
# ===================================================================


def is_terminal_status(status: str) -> bool:
    return status in _TERMINAL_STATUSES


def _ema(old: float, new: float, alpha: float = 0.3) -> float:
    """Exponential moving average helper."""
    return alpha * new + (1.0 - alpha) * old


# ===================================================================
# DATACLASSES -- Core
# ===================================================================


@dataclass
class AgentMessage:
    message_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    msg_type: MessageType = MessageType.BROADCAST
    sender: str = ""
    recipient: str = ""
    subject: str = ""
    payload: dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)
    read: bool = False
    priority: int = 5

    def to_dict(self) -> dict[str, Any]:
        return {
            "message_id": self.message_id,
            "msg_type": self.msg_type.value,
            "sender": self.sender, "recipient": self.recipient,
            "subject": self.subject, "payload": self.payload,
            "timestamp": self.timestamp, "read": self.read,
            "priority": self.priority,
        }


@dataclass
class ProgressTracker:
    tool_use_count: int = 0
    recent_activities: list[str] = field(default_factory=list)
    phase: str = ""
    percent_complete: float = 0.0
    last_update: float = field(default_factory=time.time)

    def record_activity(self, activity: str) -> None:
        self.tool_use_count += 1
        self.recent_activities.append(activity)
        if len(self.recent_activities) > 20:
            self.recent_activities = self.recent_activities[-20:]
        self.last_update = time.time()

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool_use_count": self.tool_use_count,
            "recent_activities": self.recent_activities[-5:],
            "phase": self.phase, "percent_complete": self.percent_complete,
            "last_update": self.last_update,
        }


@dataclass
class UsageTracker:
    tasks_run: int = 0
    total_wall_time_s: float = 0.0
    tool_invocations: int = 0
    findings_produced: int = 0
    errors_encountered: int = 0
    last_active: float = 0.0

    def record_task(self, duration_s: float, tools_used: int = 0, findings: int = 0) -> None:
        self.tasks_run += 1
        self.total_wall_time_s += duration_s
        self.tool_invocations += tools_used
        self.findings_produced += findings
        self.last_active = time.time()

    def to_dict(self) -> dict[str, Any]:
        return {
            "tasks_run": self.tasks_run,
            "total_wall_time_s": round(self.total_wall_time_s, 2),
            "tool_invocations": self.tool_invocations,
            "findings_produced": self.findings_produced,
            "errors_encountered": self.errors_encountered,
            "last_active": self.last_active,
        }


@dataclass
class TaskNotification:
    task_id: str = ""
    agent_id: str = ""
    role: str = ""
    status: str = ""
    summary: str = ""
    result_keys: list[str] = field(default_factory=list)
    duration_s: float = 0.0
    tool_use_count: int = 0
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id, "agent_id": self.agent_id,
            "role": self.role, "status": self.status,
            "summary": self.summary, "result_keys": self.result_keys,
            "duration_s": round(self.duration_s, 2),
            "tool_use_count": self.tool_use_count,
            "timestamp": self.timestamp,
        }


@dataclass
class TaskAssignment:
    task_id: str = ""
    description: str = ""
    instructions: str = ""
    assigned_to: str = ""
    assigned_by: str = "coordinator"
    priority: int = 5
    context: dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)
    completed_at: float | None = None
    status: str = "pending"
    result: dict[str, Any] | None = None
    progress: ProgressTracker = field(default_factory=ProgressTracker)
    abort_reason: str = ""

    def is_terminal(self) -> bool:
        return is_terminal_status(self.status)

    def to_dict(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id, "description": self.description,
            "instructions": self.instructions,
            "assigned_to": self.assigned_to, "assigned_by": self.assigned_by,
            "priority": self.priority, "context": self.context,
            "created_at": self.created_at, "completed_at": self.completed_at,
            "status": self.status, "result": self.result,
            "progress": self.progress.to_dict(),
            "abort_reason": self.abort_reason,
        }


@dataclass
class AgentOpinion:
    agent_id: str = ""
    role: str = ""
    confidence: float = 0.5
    assessment: str = ""
    evidence: list[str] = field(default_factory=list)
    dissent_from: str = ""
    recommendation: str = ""
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent_id": self.agent_id, "role": self.role,
            "confidence": self.confidence, "assessment": self.assessment,
            "evidence": self.evidence, "dissent_from": self.dissent_from,
            "recommendation": self.recommendation,
            "timestamp": self.timestamp,
        }


@dataclass
class DeliberationRound:
    round_id: str = field(default_factory=lambda: uuid.uuid4().hex[:8])
    challenger: str = ""
    defender: str = ""
    topic: str = ""
    challenger_opinion: AgentOpinion | None = None
    defender_opinion: AgentOpinion | None = None
    resolution: str = ""
    winner: str = ""
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "round_id": self.round_id,
            "challenger": self.challenger, "defender": self.defender,
            "topic": self.topic,
            "challenger_opinion": self.challenger_opinion.to_dict() if self.challenger_opinion else None,
            "defender_opinion": self.defender_opinion.to_dict() if self.defender_opinion else None,
            "resolution": self.resolution, "winner": self.winner,
            "timestamp": self.timestamp,
        }


@dataclass
class MemoryInjection:
    injection_id: str = field(default_factory=lambda: uuid.uuid4().hex[:8])
    pattern_type: str = ""
    content: str = ""
    confidence: float = 0.5
    target_roles: list[str] = field(default_factory=list)
    override_strength: float = 0.0
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "injection_id": self.injection_id,
            "pattern_type": self.pattern_type, "content": self.content,
            "confidence": self.confidence,
            "target_roles": self.target_roles,
            "override_strength": self.override_strength,
            "timestamp": self.timestamp,
        }


@dataclass
class PlaybookSuggestion:
    suggestion_id: str = field(default_factory=lambda: uuid.uuid4().hex[:8])
    name: str = ""
    description: str = ""
    steps: list[str] = field(default_factory=list)
    success_rate: float = 0.0
    confidence: float = 0.5
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "suggestion_id": self.suggestion_id,
            "name": self.name, "description": self.description,
            "steps": self.steps, "success_rate": self.success_rate,
            "confidence": self.confidence, "timestamp": self.timestamp,
        }


@dataclass
class StrategicPlan:
    plan_id: str = field(default_factory=lambda: uuid.uuid4().hex[:8])
    objective: str = ""
    phases: list[dict[str, Any]] = field(default_factory=list)
    agent_assignments: dict[str, list[str]] = field(default_factory=dict)
    estimated_duration_s: float = 0.0
    confidence: float = 0.5
    status: str = "draft"
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "plan_id": self.plan_id, "objective": self.objective,
            "phases": self.phases,
            "agent_assignments": self.agent_assignments,
            "estimated_duration_s": self.estimated_duration_s,
            "confidence": self.confidence,
            "status": self.status, "timestamp": self.timestamp,
        }


@dataclass
class DispatchRecord:
    task_id: str = ""
    role: str = ""
    description: str = ""
    context_keys: list[str] = field(default_factory=list)
    status: str = "pending"
    dispatched_at: float = field(default_factory=time.time)
    completed_at: float | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id, "role": self.role,
            "description": self.description,
            "context_keys": self.context_keys,
            "status": self.status,
            "dispatched_at": self.dispatched_at,
            "completed_at": self.completed_at,
        }


@dataclass
class AgentCapabilities:
    allowed_tools: list[str] = field(default_factory=list)
    disallowed_tools: list[str] = field(default_factory=list)
    max_parallel_tasks: int = 1
    can_spawn_subagents: bool = False
    read_only: bool = True
    execution_mode: ExecutionMode = ExecutionMode.SEQUENTIAL
    max_turns: int = 50
    timeout_s: float = 300.0
    color: str = "cyan"
    memory_scope: str = "local"
    permission_mode: PermissionMode = PermissionMode.DEFAULT
    token_budget: int = 0


# ===================================================================
# E-GAP 1: Agent Learning Profile
# ===================================================================


@dataclass
class AgentLearningProfile:
    """E-GAP 1: Quantitative performance profile that evolves over time.

    Inspired by Anthropic\\'s MEMORY.md per-agent accumulation, but goes beyond
    unstructured markdown to a quantitative scored profile. Each agent tracks:
      - success_rate: EMA of task completion
      - false_positive_rate: EMA of findings later invalidated
      - tool_mastery: per-tool success scores
      - technique_affinity: which attack categories this agent excels at
      - avg_task_duration_s: EMA of execution speed
      - specialization_score: how focused this agent has become (0-1)
    """
    tasks_attempted: int = 0
    tasks_succeeded: int = 0
    tasks_failed: int = 0
    success_rate: float = 0.5
    false_positive_rate: float = 0.0
    avg_task_duration_s: float = 0.0
    tool_mastery: dict[str, float] = field(default_factory=dict)
    technique_affinity: dict[str, float] = field(default_factory=dict)
    specialization_score: float = 0.0
    confidence_calibration: float = 0.5
    streak: int = 0
    best_streak: int = 0
    last_updated: float = field(default_factory=time.time)

    def record_success(self, duration_s: float, tools_used: list[str] | None = None,
                       techniques: list[str] | None = None) -> None:
        self.tasks_attempted += 1
        self.tasks_succeeded += 1
        self.streak = max(0, self.streak) + 1
        self.best_streak = max(self.best_streak, self.streak)
        raw_rate = self.tasks_succeeded / max(1, self.tasks_attempted)
        self.success_rate = _ema(self.success_rate, raw_rate)
        self.avg_task_duration_s = _ema(self.avg_task_duration_s, duration_s)
        for tool in (tools_used or []):
            old = self.tool_mastery.get(tool, 0.5)
            self.tool_mastery[tool] = _ema(old, 1.0)
        for tech in (techniques or []):
            old = self.technique_affinity.get(tech, 0.5)
            self.technique_affinity[tech] = _ema(old, 1.0)
        self._recompute_specialization()
        self.last_updated = time.time()

    def record_failure(self, tools_used: list[str] | None = None,
                       techniques: list[str] | None = None) -> None:
        self.tasks_attempted += 1
        self.tasks_failed += 1
        self.streak = min(0, self.streak) - 1
        raw_rate = self.tasks_succeeded / max(1, self.tasks_attempted)
        self.success_rate = _ema(self.success_rate, raw_rate)
        for tool in (tools_used or []):
            old = self.tool_mastery.get(tool, 0.5)
            self.tool_mastery[tool] = _ema(old, 0.0)
        for tech in (techniques or []):
            old = self.technique_affinity.get(tech, 0.5)
            self.technique_affinity[tech] = _ema(old, 0.0)
        self._recompute_specialization()
        self.last_updated = time.time()

    def record_false_positive(self) -> None:
        self.false_positive_rate = _ema(self.false_positive_rate, 1.0)

    def record_true_positive(self) -> None:
        self.false_positive_rate = _ema(self.false_positive_rate, 0.0)

    def _recompute_specialization(self) -> None:
        if not self.technique_affinity:
            self.specialization_score = 0.0
            return
        values = list(self.technique_affinity.values())
        mean = sum(values) / len(values)
        if mean == 0:
            self.specialization_score = 0.0
            return
        variance = sum((v - mean) ** 2 for v in values) / len(values)
        cv = math.sqrt(variance) / max(mean, 0.01)
        self.specialization_score = min(1.0, cv)

    def fitness_for_task(self, required_tools: list[str] | None = None,
                         required_techniques: list[str] | None = None) -> float:
        """Compute fitness score (0-1) for a specific task."""
        base = self.success_rate * 0.4 + (1.0 - self.false_positive_rate) * 0.2

        tool_fit = 0.5
        if required_tools:
            scores = [self.tool_mastery.get(t, 0.5) for t in required_tools]
            tool_fit = sum(scores) / len(scores)

        tech_fit = 0.5
        if required_techniques:
            scores = [self.technique_affinity.get(t, 0.5) for t in required_techniques]
            tech_fit = sum(scores) / len(scores)

        return base + tool_fit * 0.2 + tech_fit * 0.2

    def to_dict(self) -> dict[str, Any]:
        return {
            "tasks_attempted": self.tasks_attempted,
            "tasks_succeeded": self.tasks_succeeded,
            "tasks_failed": self.tasks_failed,
            "success_rate": round(self.success_rate, 3),
            "false_positive_rate": round(self.false_positive_rate, 3),
            "avg_task_duration_s": round(self.avg_task_duration_s, 2),
            "tool_mastery": {k: round(v, 3) for k, v in
                            sorted(self.tool_mastery.items(), key=lambda x: -x[1])[:10]},
            "technique_affinity": {k: round(v, 3) for k, v in
                                   sorted(self.technique_affinity.items(), key=lambda x: -x[1])[:10]},
            "specialization_score": round(self.specialization_score, 3),
            "confidence_calibration": round(self.confidence_calibration, 3),
            "streak": self.streak,
            "best_streak": self.best_streak,
            "last_updated": self.last_updated,
        }


# ===================================================================
# E-GAP 2: Conflict Resolution Engine
# ===================================================================


@dataclass
class ConflictPosition:
    """A single agent\\'s position in a structured conflict."""
    agent_id: str = ""
    role: str = ""
    claim: str = ""
    confidence: float = 0.5
    evidence: list[str] = field(default_factory=list)
    evidence_strength: float = 0.5
    counter_arguments: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent_id": self.agent_id, "role": self.role,
            "claim": self.claim, "confidence": self.confidence,
            "evidence": self.evidence,
            "evidence_strength": self.evidence_strength,
            "counter_arguments": self.counter_arguments,
        }


@dataclass
class ConflictResolution:
    """E-GAP 2: Result of a structured conflict resolution process."""
    conflict_id: str = field(default_factory=lambda: uuid.uuid4().hex[:8])
    topic: str = ""
    positions: list[ConflictPosition] = field(default_factory=list)
    method: ConflictResolutionMethod = ConflictResolutionMethod.WEIGHTED_VOTE
    winner: str = ""
    winning_claim: str = ""
    margin: float = 0.0
    rounds_taken: int = 1
    escalated: bool = False
    rationale: str = ""
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "conflict_id": self.conflict_id, "topic": self.topic,
            "positions": [p.to_dict() for p in self.positions],
            "method": self.method.value,
            "winner": self.winner, "winning_claim": self.winning_claim,
            "margin": round(self.margin, 3),
            "rounds_taken": self.rounds_taken,
            "escalated": self.escalated,
            "rationale": self.rationale,
            "timestamp": self.timestamp,
        }


# ===================================================================
# E-GAP 3: Pre-Decision Memory Recall
# ===================================================================


@dataclass
class MemoryRecallEntry:
    """E-GAP 3: A recalled memory relevant to the current decision."""
    entry_id: str = field(default_factory=lambda: uuid.uuid4().hex[:8])
    category: str = ""       # target_pattern, technique_outcome, platform_trait
    content: str = ""
    relevance_score: float = 0.0
    source_agent: str = ""
    original_target: str = ""
    recency_weight: float = 1.0
    times_recalled: int = 0
    created_at: float = field(default_factory=time.time)
    last_recalled: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "entry_id": self.entry_id, "category": self.category,
            "content": self.content,
            "relevance_score": round(self.relevance_score, 3),
            "source_agent": self.source_agent,
            "original_target": self.original_target,
            "recency_weight": round(self.recency_weight, 3),
            "times_recalled": self.times_recalled,
            "created_at": self.created_at,
            "last_recalled": self.last_recalled,
        }


@dataclass
class PreDecisionBrief:
    """E-GAP 3: A compiled brief injected into an agent BEFORE it executes.

    Modeled after Anthropic\\'s buildMemoryPrompt() + findRelevantMemories()
    pattern, adapted for pentesting context.
    """
    brief_id: str = field(default_factory=lambda: uuid.uuid4().hex[:8])
    target_role: str = ""
    task_description: str = ""
    recalled_memories: list[MemoryRecallEntry] = field(default_factory=list)
    suppressions: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    confidence: float = 0.5
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "brief_id": self.brief_id,
            "target_role": self.target_role,
            "task_description": self.task_description,
            "recalled_memories": [m.to_dict() for m in self.recalled_memories],
            "suppressions": self.suppressions,
            "recommendations": self.recommendations,
            "confidence": round(self.confidence, 3),
            "timestamp": self.timestamp,
        }


# ===================================================================
# E-GAP 4: Simulation / Prediction Layer
# ===================================================================


@dataclass
class SimulationScenario:
    """E-GAP 4: A predicted outcome of a candidate action."""
    scenario_id: str = field(default_factory=lambda: uuid.uuid4().hex[:8])
    action: str = ""
    predicted_findings: int = 0
    predicted_duration_s: float = 0.0
    detection_risk: float = 0.0
    success_probability: float = 0.5
    resource_cost: float = 0.0
    expected_value: float = 0.0
    side_effects: list[str] = field(default_factory=list)

    def compute_expected_value(self) -> float:
        reward = self.predicted_findings * self.success_probability
        cost = self.detection_risk * 0.3 + self.resource_cost * 0.2
        ev = reward - cost
        self.expected_value = ev
        return ev

    def to_dict(self) -> dict[str, Any]:
        return {
            "scenario_id": self.scenario_id, "action": self.action,
            "predicted_findings": self.predicted_findings,
            "predicted_duration_s": round(self.predicted_duration_s, 2),
            "detection_risk": round(self.detection_risk, 3),
            "success_probability": round(self.success_probability, 3),
            "resource_cost": round(self.resource_cost, 3),
            "expected_value": round(self.expected_value, 3),
            "side_effects": self.side_effects,
        }


@dataclass
class SimulationResult:
    """E-GAP 4: Full simulation comparison of candidate actions."""
    simulation_id: str = field(default_factory=lambda: uuid.uuid4().hex[:8])
    scenarios: list[SimulationScenario] = field(default_factory=list)
    recommended_action: str = ""
    recommendation_reason: str = ""
    confidence: float = 0.5
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "simulation_id": self.simulation_id,
            "scenarios": [s.to_dict() for s in self.scenarios],
            "recommended_action": self.recommended_action,
            "recommendation_reason": self.recommendation_reason,
            "confidence": round(self.confidence, 3),
            "timestamp": self.timestamp,
        }


# ===================================================================
# E-GAP 5: Strategic Arc
# ===================================================================


@dataclass
class StrategicArc:
    """E-GAP 5: A multi-phase strategic arc that evolves based on results.

    Modeled after Anthropic\\'s Research -> Synthesis -> Implementation -> Verification
    coordinator workflow, but adapted to pentesting phases with arc-level
    state tracking and inter-phase adaptation.
    """
    arc_id: str = field(default_factory=lambda: uuid.uuid4().hex[:8])
    objective: str = ""
    current_phase: StrategyArcPhase = StrategyArcPhase.RECONNAISSANCE
    phase_history: list[dict[str, Any]] = field(default_factory=list)
    pivot_count: int = 0
    max_pivots: int = 3
    accumulated_findings: list[str] = field(default_factory=list)
    decisions_made: list[dict[str, Any]] = field(default_factory=list)
    phase_outcomes: dict[str, dict[str, Any]] = field(default_factory=dict)
    confidence_trajectory: list[float] = field(default_factory=list)
    status: str = "active"
    started_at: float = field(default_factory=time.time)
    completed_at: float | None = None

    def advance_phase(self, next_phase: StrategyArcPhase, reason: str = "",
                      outcome: dict[str, Any] | None = None) -> None:
        self.phase_history.append({
            "phase": self.current_phase.value,
            "transitioned_to": next_phase.value,
            "reason": reason,
            "outcome": outcome or {},
            "timestamp": time.time(),
        })
        if outcome:
            self.phase_outcomes[self.current_phase.value] = outcome
        self.current_phase = next_phase

    def record_pivot(self, reason: str, new_objective: str = "") -> bool:
        if self.pivot_count >= self.max_pivots:
            return False
        self.pivot_count += 1
        self.decisions_made.append({
            "type": "pivot",
            "reason": reason,
            "new_objective": new_objective or self.objective,
            "pivot_number": self.pivot_count,
            "timestamp": time.time(),
        })
        if new_objective:
            self.objective = new_objective
        self.current_phase = StrategyArcPhase.PIVOT
        return True

    def complete(self, final_outcome: dict[str, Any] | None = None) -> None:
        self.status = "completed"
        self.completed_at = time.time()
        if final_outcome:
            self.phase_outcomes["final"] = final_outcome

    def to_dict(self) -> dict[str, Any]:
        return {
            "arc_id": self.arc_id, "objective": self.objective,
            "current_phase": self.current_phase.value,
            "phase_history": self.phase_history[-10:],
            "pivot_count": self.pivot_count,
            "max_pivots": self.max_pivots,
            "accumulated_findings_count": len(self.accumulated_findings),
            "decisions_made": self.decisions_made[-10:],
            "phase_outcomes": {k: v for k, v in list(self.phase_outcomes.items())[-5:]},
            "confidence_trajectory": self.confidence_trajectory[-20:],
            "status": self.status,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
        }


# ===================================================================
# ROLE DEFINITIONS
# ===================================================================

AGENT_ROLE_DEFINITIONS: dict[str, dict[str, Any]] = {
    "recon": {
        "name": "Recon Agent",
        "description": "Discovery specialist: subdomains, ports, tech fingerprinting, crawling, content discovery.",
        "priority": 1,
        "phases": [
            "dns", "subdomain", "port_scan", "tech_fingerprint",
            "crawl", "content_discovery", "js_analysis", "param_discovery",
        ],
        "produces": ["subdomains", "endpoints", "technologies", "open_ports", "parameters"],
        "consumes": ["constraints", "stealth_config"],
        "capabilities": AgentCapabilities(
            allowed_tools=[
                "subfinder", "amass", "httpx", "nmap", "nuclei",
                "katana", "gospider", "ffuf", "dirsearch", "gau",
                "waybackurls", "jsluice", "linkfinder", "arjun",
            ],
            max_parallel_tasks=4, read_only=True,
            execution_mode=ExecutionMode.PARALLEL, max_turns=100,
            timeout_s=300.0, color=AGENT_COLORS["recon"],
            memory_scope="project",
            permission_mode=PermissionMode.ACCEPT_RESULTS,
        ),
    },
    "exploit": {
        "name": "Exploit Agent",
        "description": "Validation specialist: vulnerability scanning, injection testing, PoC generation, proof of impact.",
        "priority": 3,
        "phases": [
            "vuln_scan", "injection_test", "auth_test",
            "exploit_verify", "poc_gen", "impact_demo",
        ],
        "produces": ["findings", "pocs", "exploit_chains"],
        "consumes": ["endpoints", "parameters", "technologies", "attack_paths"],
        "capabilities": AgentCapabilities(
            allowed_tools=[
                "nuclei", "sqlmap", "xsstrike", "commix", "dalfox",
                "tplmap", "ssrfmap", "crlfuzz", "corsy",
            ],
            max_parallel_tasks=2, read_only=False,
            execution_mode=ExecutionMode.SEQUENTIAL, max_turns=50,
            timeout_s=600.0, color=AGENT_COLORS["exploit"],
            memory_scope="project",
            permission_mode=PermissionMode.DEFAULT,
        ),
    },
    "strategy": {
        "name": "Strategy Agent",
        "description": "Prioritization specialist: phase ordering, budget allocation, mode selection, attack path planning.",
        "priority": 2,
        "phases": ["planning", "prioritization", "resource_allocation"],
        "produces": ["current_strategy", "attack_paths", "phase_priorities", "budget"],
        "consumes": ["subdomains", "endpoints", "technologies", "findings", "constraints"],
        "capabilities": AgentCapabilities(
            allowed_tools=[], max_parallel_tasks=1, read_only=True,
            execution_mode=ExecutionMode.ADVISORY, max_turns=30,
            timeout_s=60.0, color=AGENT_COLORS["strategy"],
            memory_scope="local",
            permission_mode=PermissionMode.RESTRICTED,
        ),
    },
    "memory": {
        "name": "Memory Agent",
        "description": "Learning specialist: cross-scan pattern recognition, episode recall, knowledge consolidation.",
        "priority": 5,
        "phases": ["recall", "consolidation", "pattern_extraction"],
        "produces": ["recalled_episodes", "platform_stats", "playbook_suggestions"],
        "consumes": ["findings", "technologies", "endpoints", "current_strategy"],
        "capabilities": AgentCapabilities(
            allowed_tools=[], max_parallel_tasks=1, read_only=False,
            execution_mode=ExecutionMode.ADVISORY, max_turns=20,
            timeout_s=60.0, color=AGENT_COLORS["memory"],
            memory_scope="user",
            permission_mode=PermissionMode.ACCEPT_RESULTS,
        ),
    },
    "defense": {
        "name": "Defense Agent",
        "description": "Evasion specialist: WAF bypass, stealth mode, rate-limit management, detection risk assessment.",
        "priority": 0,
        "phases": ["waf_detect", "evasion_profile", "rate_limit", "stealth_config"],
        "produces": ["waf_vendor", "evasion_profile", "rate_limits", "detection_risk", "stealth_config"],
        "consumes": ["endpoints", "technologies", "constraints"],
        "capabilities": AgentCapabilities(
            allowed_tools=["wafw00f", "whatwaf", "bypass-403"],
            max_parallel_tasks=1, read_only=True,
            execution_mode=ExecutionMode.PARALLEL, max_turns=40,
            timeout_s=120.0, color=AGENT_COLORS["defense"],
            memory_scope="project",
            permission_mode=PermissionMode.DEFAULT,
        ),
    },
}


# ===================================================================
# SHARED CONTEXT
# ===================================================================


class SharedContext:
    """Thread-safe shared state across all specialist agents."""

    _KEYS = frozenset([
        "subdomains", "endpoints", "technologies", "open_ports", "parameters",
        "findings", "pocs", "exploit_chains", "current_strategy", "attack_paths",
        "budget", "phase_priorities", "directives", "recalled_episodes",
        "platform_stats", "waf_vendor", "evasion_profile", "rate_limits",
        "detection_risk", "stealth_config", "constraints",
    ])

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._data: dict[str, Any] = {
            k: [] for k in self._KEYS
            if k not in ("budget", "current_strategy", "waf_vendor", "detection_risk")
        }
        self._data["budget"] = {"total": 1.0, "used": 0.0}
        self._data["detection_risk"] = 0.0
        self._data["waf_vendor"] = ""
        self._data["current_strategy"] = {}
        self._version = 0
        self._change_log: deque[dict[str, Any]] = deque(maxlen=100)

    def get(self, key: str, default: Any = None) -> Any:
        with self._lock:
            return self._data.get(key, default)

    def set(self, key: str, value: Any, source: str = "") -> None:
        with self._lock:
            self._data[key] = value
            self._version += 1
            self._change_log.append({
                "key": key, "source": source,
                "version": self._version, "ts": time.time(),
            })

    def append(self, key: str, value: Any, source: str = "") -> None:
        with self._lock:
            current = self._data.get(key)
            if isinstance(current, list):
                current.append(value)
            elif isinstance(current, dict) and isinstance(value, dict):
                current.update(value)
            self._version += 1
            self._change_log.append({
                "key": key, "action": "append", "source": source,
                "version": self._version, "ts": time.time(),
            })

    def merge(self, updates: dict[str, Any], source: str = "") -> None:
        with self._lock:
            for k, v in updates.items():
                if k in self._data:
                    current = self._data[k]
                    if isinstance(current, list) and isinstance(v, list):
                        current.extend(v)
                    elif isinstance(current, dict) and isinstance(v, dict):
                        current.update(v)
                    else:
                        self._data[k] = v
            self._version += 1
            self._change_log.append({
                "action": "merge", "keys": list(updates.keys()),
                "source": source, "version": self._version, "ts": time.time(),
            })

    def snapshot(self) -> dict[str, Any]:
        import copy
        with self._lock:
            return copy.deepcopy(self._data)

    def active_keys(self) -> list[str]:
        with self._lock:
            result = []
            for k, v in self._data.items():
                if isinstance(v, list) and len(v) > 0:
                    result.append(k)
                elif isinstance(v, dict) and len(v) > 0:
                    result.append(k)
                elif not isinstance(v, (list, dict)) and v:
                    result.append(k)
            return result

    def to_dict(self) -> dict[str, Any]:
        with self._lock:
            summary: dict[str, Any] = {}
            for k, v in self._data.items():
                if isinstance(v, list):
                    summary[k] = {"count": len(v), "sample": v[:3] if v else []}
                elif isinstance(v, dict):
                    summary[k] = v
                else:
                    summary[k] = v
            summary["_version"] = self._version
            summary["_changes"] = len(self._change_log)
            return summary


# ===================================================================
# E-GAP 3: Memory Index (pre-decision recall store)
# ===================================================================


class MemoryIndex:
    """E-GAP 3: Indexed memory store for pre-decision recall.

    Inspired by Anthropic\\'s findRelevantMemories() sidequery pattern.
    Stores observations as MemoryRecallEntry objects, supports relevance-scored
    retrieval by category, target, technique, or general keyword matching.
    """

    def __init__(self, max_entries: int = 500) -> None:
        self._lock = threading.Lock()
        self._entries: deque[MemoryRecallEntry] = deque(maxlen=max_entries)
        self._category_index: dict[str, list[str]] = {}

    def store(self, category: str, content: str, source_agent: str = "",
              target: str = "", relevance: float = 0.5) -> MemoryRecallEntry:
        entry = MemoryRecallEntry(
            category=category, content=content,
            relevance_score=relevance, source_agent=source_agent,
            original_target=target,
        )
        with self._lock:
            self._entries.append(entry)
            self._category_index.setdefault(category, []).append(entry.entry_id)
        return entry

    def recall(self, query_terms: list[str], category: str = "",
               max_results: int = 5, min_relevance: float = 0.1) -> list[MemoryRecallEntry]:
        """Retrieve memories matching query terms, ranked by relevance * recency."""
        now = time.time()
        scored: list[tuple[float, MemoryRecallEntry]] = []

        with self._lock:
            for entry in self._entries:
                if category and entry.category != category:
                    continue
                if entry.relevance_score < min_relevance:
                    continue

                text_match = 0.0
                content_lower = entry.content.lower()
                for term in query_terms:
                    if term.lower() in content_lower:
                        text_match += 1.0
                if query_terms:
                    text_match /= len(query_terms)

                age_hours = (now - entry.created_at) / 3600.0
                recency = 1.0 / (1.0 + age_hours * 0.1)

                score = (
                    entry.relevance_score * 0.4
                    + text_match * 0.4
                    + recency * 0.2
                )

                if score > min_relevance:
                    scored.append((score, entry))

        scored.sort(key=lambda x: -x[0])
        results = []
        for _score, entry in scored[:max_results]:
            entry.times_recalled += 1
            entry.last_recalled = now
            results.append(entry)
        return results

    def store_outcome(self, target: str, technique: str, success: bool,
                      details: str = "") -> MemoryRecallEntry:
        """Convenience: store a technique outcome for future recall."""
        category = "technique_success" if success else "technique_failure"
        content = f"{technique} on {target}: {'SUCCESS' if success else 'FAILED'}. {details}"
        return self.store(
            category=category, content=content,
            target=target, relevance=0.8 if success else 0.6,
        )

    def store_platform_pattern(self, platform: str, pattern: str,
                               confidence: float = 0.7) -> MemoryRecallEntry:
        """Convenience: store a platform-specific observation."""
        return self.store(
            category="platform_pattern",
            content=f"{platform}: {pattern}",
            relevance=confidence,
        )

    def get_stats(self) -> dict[str, Any]:
        with self._lock:
            return {
                "total_entries": len(self._entries),
                "categories": {k: len(v) for k, v in self._category_index.items()},
            }

    def to_dict(self) -> dict[str, Any]:
        with self._lock:
            return {
                "total_entries": len(self._entries),
                "categories": {k: len(v) for k, v in self._category_index.items()},
                "recent_entries": [e.to_dict() for e in list(self._entries)[-10:]],
            }


# ===================================================================
# AGENT MAILBOX
# ===================================================================


class AgentMailbox:
    """In-memory typed message bus with auto-resume and dead-task guard."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._inboxes: dict[str, deque[AgentMessage]] = {}
        self._subscribers: dict[str, list[Callable[[AgentMessage], None]]] = {}
        self._message_history: deque[AgentMessage] = deque(maxlen=500)
        self._retired_agents: set[str] = set()
        self._resume_callbacks: dict[str, Callable[[str], None]] = {}
        self._agent_states: dict[str, str] = {}
        self._pending_queues: dict[str, deque[AgentMessage]] = {}

    def register(self, agent_id: str) -> None:
        with self._lock:
            if agent_id not in self._inboxes:
                self._inboxes[agent_id] = deque(maxlen=200)
                self._subscribers[agent_id] = []
                self._agent_states[agent_id] = "idle"

    def unregister(self, agent_id: str) -> None:
        with self._lock:
            self._retired_agents.add(agent_id)
            self._inboxes.pop(agent_id, None)
            self._subscribers.pop(agent_id, None)
            self._resume_callbacks.pop(agent_id, None)
            self._pending_queues.pop(agent_id, None)
            self._agent_states.pop(agent_id, None)

    def subscribe(self, agent_id: str, callback: Callable[[AgentMessage], None]) -> None:
        with self._lock:
            if agent_id in self._subscribers:
                self._subscribers[agent_id].append(callback)

    def set_resume_callback(self, agent_id: str, callback: Callable[[str], None]) -> None:
        with self._lock:
            self._resume_callbacks[agent_id] = callback

    def update_agent_state(self, agent_id: str, state: str) -> None:
        with self._lock:
            self._agent_states[agent_id] = state

    def drain_pending(self, agent_id: str) -> list[AgentMessage]:
        with self._lock:
            pending = self._pending_queues.pop(agent_id, deque())
            return list(pending)

    def send(self, message: AgentMessage) -> bool:
        resume_cb: Callable[[str], None] | None = None
        resume_target: str = ""

        with self._lock:
            recipient = message.recipient
            subs_to_notify: list[Callable[[AgentMessage], None]] = []
            if recipient == "*":
                for aid, inbox in self._inboxes.items():
                    if aid != message.sender and aid not in self._retired_agents:
                        inbox.append(message)
                self._message_history.append(message)
                for aid, subs in self._subscribers.items():
                    if aid != message.sender and aid not in self._retired_agents:
                        subs_to_notify.extend(subs)
            elif recipient in self._retired_agents:
                return False
            elif recipient in self._inboxes:
                agent_state = self._agent_states.get(recipient, "idle")
                if agent_state in ("completed", "failed", "idle"):
                    if recipient not in self._pending_queues:
                        self._pending_queues[recipient] = deque(maxlen=50)
                    self._pending_queues[recipient].append(message)
                    self._message_history.append(message)
                    if recipient in self._resume_callbacks:
                        resume_cb = self._resume_callbacks[recipient]
                        resume_target = recipient
                else:
                    self._inboxes[recipient].append(message)
                    self._message_history.append(message)
                    subs_to_notify = list(self._subscribers.get(recipient, []))
            else:
                return False

        for cb in subs_to_notify:
            try:
                cb(message)
            except Exception:
                logger.exception("Subscriber callback failed")

        if resume_cb and resume_target:
            try:
                resume_cb(resume_target)
            except Exception:
                logger.exception("Auto-resume callback failed for %s", resume_target)

        return True

    def read_inbox(self, agent_id: str, mark_read: bool = True) -> list[AgentMessage]:
        with self._lock:
            inbox = self._inboxes.get(agent_id, deque())
            messages = list(inbox)
            if mark_read:
                for m in messages:
                    m.read = True
            return messages

    def get_history(self, limit: int = 50) -> list[AgentMessage]:
        with self._lock:
            return list(self._message_history)[-limit:]

    def to_dict(self) -> dict[str, Any]:
        with self._lock:
            return {
                "agents": list(self._inboxes.keys()),
                "retired": list(self._retired_agents),
                "inbox_sizes": {k: len(v) for k, v in self._inboxes.items()},
                "pending_sizes": {k: len(v) for k, v in self._pending_queues.items()},
                "history_size": len(self._message_history),
                "recent_messages": [m.to_dict() for m in list(self._message_history)[-10:]],
            }


# ===================================================================
# SPECIALIST AGENT
# ===================================================================


class SpecialistAgent:
    """A role-bound specialist agent with identity evolution, conflict participation,
    pre-decision memory recall, and simulation capability.
    """

    def __init__(
        self,
        role: AgentRoleType,
        shared_context: SharedContext,
        mailbox: AgentMailbox,
        memory_index: MemoryIndex | None = None,
        execute_fn: Callable[..., dict[str, Any]] | None = None,
        on_state_change: Callable[[str, AgentState, AgentState], None] | None = None,
    ) -> None:
        self.role = role
        self.role_def = AGENT_ROLE_DEFINITIONS[role.value]
        self.agent_id = f"{role.value}-{uuid.uuid4().hex[:6]}"
        self.capabilities: AgentCapabilities = self.role_def["capabilities"]

        self._shared_context = shared_context
        self._mailbox = mailbox
        self._memory_index = memory_index
        self._execute_fn = execute_fn
        self._on_state_change = on_state_change

        # State
        self._state = AgentState.IDLE
        self._current_task: TaskAssignment | None = None
        self._task_history: deque[TaskAssignment] = deque(maxlen=50)
        self._working_memory: dict[str, Any] = {}
        self._thread: threading.Thread | None = None
        self._stats: dict[str, Any] = {
            "tasks_completed": 0, "tasks_failed": 0,
            "total_time_s": 0.0, "last_active": 0.0,
        }

        # Abort tracking
        self._turn_count = 0
        self._abort_event = threading.Event()
        self._abort_reason: AbortReason | None = None
        self._spawned_children: list[str] = []

        # Scoped memory
        self._memory_store: dict[str, dict[str, Any]] = {
            "user": {}, "project": {}, "local": {},
        }

        # Lifecycle hooks
        self._cleanup_hooks: dict[HookPhase, list[Callable[[], None]]] = {
            phase: [] for phase in HookPhase
        }

        # Usage tracking
        self._usage = UsageTracker()

        # Diminishing returns
        self._consecutive_low_output: int = 0
        self._LOW_OUTPUT_THRESHOLD = 3

        # Opinions and confidence
        self._opinions: deque[AgentOpinion] = deque(maxlen=20)
        self._confidence: float = 0.5
        self._dissent_threshold: float = 0.3

        # Permission mode
        self._effective_permission: PermissionMode = self.capabilities.permission_mode

        # ── E-GAP 1: Learning Profile ──
        self._learning_profile = AgentLearningProfile()

        # ── E-GAP 3: Last pre-decision brief ──
        self._last_brief: PreDecisionBrief | None = None

        # Register with mailbox
        self._mailbox.register(self.agent_id)
        self._mailbox.subscribe(self.agent_id, self._on_message)
        self._mailbox.set_resume_callback(self.agent_id, self._on_auto_resume)

    # -- State Management --

    def _set_state(self, new_state: AgentState) -> None:
        old = self._state
        self._state = new_state
        self._mailbox.update_agent_state(self.agent_id, new_state.value)
        if self._on_state_change:
            try:
                self._on_state_change(self.agent_id, old, new_state)
            except Exception:
                logger.exception("State change callback failed for %s", self.agent_id)

    @property
    def state(self) -> AgentState:
        return self._state

    @property
    def usage(self) -> UsageTracker:
        return self._usage

    @property
    def learning_profile(self) -> AgentLearningProfile:
        """E-GAP 1: Access the agent\\'s evolving learning profile."""
        return self._learning_profile

    def register_hook(self, phase: HookPhase, hook: Callable[[], None]) -> None:
        self._cleanup_hooks[phase].append(hook)

    def set_permission_mode(self, mode: PermissionMode) -> None:
        if mode.value >= self._effective_permission.value:
            self._effective_permission = mode

    def check_tool_permission(self, tool_name: str) -> bool:
        if self._effective_permission == PermissionMode.BYPASS:
            return True
        if self._effective_permission == PermissionMode.RESTRICTED:
            return tool_name in self.capabilities.allowed_tools and self.capabilities.read_only
        if tool_name in self.capabilities.disallowed_tools:
            return False
        if self.capabilities.allowed_tools and tool_name not in self.capabilities.allowed_tools:
            return False
        return True

    # -- Task Execution --

    def assign_task(self, task: TaskAssignment) -> None:
        if self._state == AgentState.RETIRED:
            logger.warning("Cannot assign task to retired agent %s", self.agent_id)
            return
        self._abort_event.clear()
        self._abort_reason = None
        self._turn_count = 0
        self._consecutive_low_output = 0
        self._current_task = task
        task.assigned_to = self.agent_id
        task.status = "running"
        self._set_state(AgentState.RUNNING)
        self._thread = threading.Thread(
            target=self._execute_task, args=(task,),
            name=f"agent-{self.agent_id}", daemon=True,
        )
        self._thread.start()

    def _execute_task(self, task: TaskAssignment) -> None:
        start = time.time()
        try:
            self._run_hooks(HookPhase.PRE_EXECUTE)

            max_turns = self.capabilities.max_turns
            timeout_s = self.capabilities.timeout_s

            # Inject permission context
            task.context["_allowed_tools"] = self.capabilities.allowed_tools
            task.context["_disallowed_tools"] = self.capabilities.disallowed_tools
            task.context["_read_only"] = self.capabilities.read_only
            task.context["_permission_mode"] = self._effective_permission.name

            # ── E-GAP 3: Pre-decision memory recall ──
            if self._memory_index and self._last_brief:
                task.context["_pre_decision_brief"] = self._last_brief.to_dict()

            # ── E-GAP 1: Inject learning profile context ──
            task.context["_agent_fitness"] = self._learning_profile.fitness_for_task(
                required_tools=self.capabilities.allowed_tools[:5],
            )
            task.context["_agent_success_rate"] = self._learning_profile.success_rate

            # Abort check 1
            if self._abort_event.is_set():
                raise _AgentAborted(
                    f"Agent {self.agent_id} aborted before execution",
                    self._abort_reason or AbortReason.USER_CANCEL,
                )

            result: dict[str, Any] = {}
            if self._execute_fn:
                result = self._execute_fn(
                    self.role.value, task.description, task.instructions,
                    task.context, self._shared_context,
                )
            else:
                result = self._default_execute(task)

            task.progress.record_activity(f"Executed task: {task.description[:50]}")
            if result:
                task.progress.percent_complete = 1.0

            self._turn_count += 1

            # Abort check 2
            if self._abort_event.is_set():
                raise _AgentAborted(
                    f"Agent {self.agent_id} aborted after execution",
                    self._abort_reason or AbortReason.USER_CANCEL,
                )

            if self._turn_count > max_turns:
                raise _AgentAborted(
                    f"Agent {self.agent_id} exceeded max_turns={max_turns}",
                    AbortReason.MAX_TURNS,
                )

            elapsed = time.time() - start
            if elapsed > timeout_s:
                raise _AgentTimeout(
                    f"Agent {self.agent_id} exceeded timeout={timeout_s}s"
                )

            # Diminishing returns
            result_size = len(result) if result else 0
            if result_size == 0:
                self._consecutive_low_output += 1
                if self._consecutive_low_output >= self._LOW_OUTPUT_THRESHOLD:
                    task.context["_diminishing_returns"] = True
            else:
                self._consecutive_low_output = 0

            # ── Success ──
            duration = time.time() - start
            task.status = "completed"
            task.result = result
            task.completed_at = time.time()
            self._stats["tasks_completed"] += 1
            self._stats["total_time_s"] += duration
            self._stats["last_active"] = time.time()
            self._task_history.append(task)

            # E-GAP 1: Update learning profile on success
            tools_used = result.get("tools_used", []) if result else []
            techniques = result.get("techniques_used", []) if result else []
            self._learning_profile.record_success(
                duration_s=duration,
                tools_used=tools_used,
                techniques=techniques,
            )

            # E-GAP 3: Store outcome in memory index
            if self._memory_index and result:
                for finding in result.get("findings", []):
                    finding_str = str(finding)[:200] if finding else ""
                    self._memory_index.store_outcome(
                        target=task.context.get("target_url", "unknown"),
                        technique=task.description[:100],
                        success=True,
                        details=finding_str,
                    )

            # Usage tracking
            findings_count = len(result.get("findings", [])) if result else 0
            self._usage.record_task(
                duration_s=duration,
                tools_used=task.progress.tool_use_count,
                findings=findings_count,
            )

            # Push results into shared context
            if result:
                for key in self.role_def.get("produces", []):
                    if key in result:
                        self._shared_context.append(key, result[key], source=self.agent_id)

            # Structured notification
            notification = TaskNotification(
                task_id=task.task_id, agent_id=self.agent_id,
                role=self.role.value, status="completed",
                summary=f"Completed: {task.description[:80]}",
                result_keys=list(result.keys()) if result else [],
                duration_s=duration,
                tool_use_count=task.progress.tool_use_count,
            )
            self._mailbox.send(AgentMessage(
                msg_type=MessageType.TASK_RESULT,
                sender=self.agent_id, recipient="coordinator",
                subject=f"Task {task.task_id} completed",
                payload=notification.to_dict(),
            ))
            self._set_state(AgentState.COMPLETED)
            self._run_hooks(HookPhase.POST_EXECUTE)

        except _AgentAborted as e:
            task.status = "aborted"
            task.abort_reason = e.reason.value
            task.completed_at = time.time()
            self._task_history.append(task)
            # E-GAP 1: record failure
            self._learning_profile.record_failure()
            self._mailbox.send(AgentMessage(
                msg_type=MessageType.TASK_FAILED,
                sender=self.agent_id, recipient="coordinator",
                subject=f"Task {task.task_id} aborted",
                payload={"task_id": task.task_id, "reason": e.reason.value},
            ))
            if e.reason == AbortReason.MAX_TURNS:
                self._set_state(AgentState.FAILED)
            else:
                self._set_state(AgentState.IDLE)
            self._run_hooks(HookPhase.ON_ABORT)

        except _AgentTimeout:
            task.status = "timeout"
            task.abort_reason = AbortReason.TIMEOUT.value
            task.completed_at = time.time()
            self._task_history.append(task)
            self._usage.errors_encountered += 1
            self._learning_profile.record_failure()
            self._mailbox.send(AgentMessage(
                msg_type=MessageType.TASK_FAILED,
                sender=self.agent_id, recipient="coordinator",
                subject=f"Task {task.task_id} timed out",
                payload={"task_id": task.task_id, "reason": "timeout"},
            ))
            self._set_state(AgentState.FAILED)

        except Exception as exc:
            task.status = "failed"
            task.completed_at = time.time()
            task.result = {"error": str(exc)}
            self._stats["tasks_failed"] += 1
            self._usage.errors_encountered += 1
            self._learning_profile.record_failure()
            self._task_history.append(task)

            # E-GAP 3: Store failure in memory index
            if self._memory_index:
                self._memory_index.store_outcome(
                    target=task.context.get("target_url", "unknown"),
                    technique=task.description[:100],
                    success=False,
                    details=str(exc)[:200],
                )

            self._mailbox.send(AgentMessage(
                msg_type=MessageType.TASK_FAILED,
                sender=self.agent_id, recipient="coordinator",
                subject=f"Task {task.task_id} failed",
                payload={"task_id": task.task_id, "error": str(exc)},
            ))
            self._set_state(AgentState.FAILED)
            logger.exception("Agent %s task failed: %s", self.agent_id, exc)

        finally:
            self._run_hooks(HookPhase.ON_CLEANUP)
            self._current_task = None

    def _run_hooks(self, phase: HookPhase) -> None:
        for hook in self._cleanup_hooks.get(phase, []):
            try:
                hook()
            except Exception:
                logger.exception("Hook %s failed for %s", phase.value, self.agent_id)

    def _default_execute(self, task: TaskAssignment) -> dict[str, Any]:
        return {
            "agent": self.agent_id, "role": self.role.value,
            "task": task.description, "status": "default_execution",
            "note": "No execute_fn provided; stub result.",
        }

    # -- Message handling --

    def _on_message(self, message: AgentMessage) -> None:
        if message.msg_type == MessageType.CONSTRAINT_ALERT:
            self._working_memory["last_constraint"] = message.payload
        elif message.msg_type == MessageType.STRATEGY_UPDATE:
            self._working_memory["current_strategy"] = message.payload
        elif message.msg_type == MessageType.HEALTH_CHECK:
            self._mailbox.send(AgentMessage(
                msg_type=MessageType.HEALTH_RESPONSE,
                sender=self.agent_id, recipient=message.sender,
                subject="Health response",
                payload={
                    "state": self._state.value,
                    "task": self._current_task.task_id if self._current_task else None,
                    "usage": self._usage.to_dict(),
                    "learning_profile": self._learning_profile.to_dict(),
                },
            ))
        elif message.msg_type == MessageType.CHALLENGE:
            topic = message.payload.get("topic", "")
            opinion = self.form_opinion(topic, message.payload)
            self._mailbox.send(AgentMessage(
                msg_type=MessageType.OPINION_SUBMIT,
                sender=self.agent_id, recipient=message.sender,
                subject=f"Counter-opinion on {topic}",
                payload=opinion.to_dict(),
            ))
        elif message.msg_type == MessageType.PEER_REQUEST:
            self._working_memory[f"peer_request_{message.sender}"] = message.payload
            self._mailbox.send(AgentMessage(
                msg_type=MessageType.PEER_RESPONSE,
                sender=self.agent_id, recipient=message.sender,
                subject=f"Peer response from {self.role.value}",
                payload={
                    "ack": True, "role": self.role.value,
                    "context_keys": list(self._working_memory.keys()),
                },
            ))
        elif message.msg_type == MessageType.MEMORY_RECALL_RESPONSE:
            # E-GAP 3: Receive pre-decision brief
            brief_data = message.payload
            if brief_data:
                self._working_memory["_pre_decision_brief"] = brief_data

    def _on_auto_resume(self, agent_id: str) -> None:
        if self._state in (AgentState.COMPLETED, AgentState.FAILED, AgentState.IDLE):
            self._set_state(AgentState.IDLE)
            self._run_hooks(HookPhase.ON_RESUME)
            pending = self._mailbox.drain_pending(agent_id)
            for msg in pending:
                self._on_message(msg)

    # -- Abort / Retire --

    def abort(self, reason: AbortReason = AbortReason.USER_CANCEL) -> bool:
        if self._state == AgentState.RUNNING:
            self._abort_reason = reason
            self._abort_event.set()
            return True
        return False

    def retire(self) -> None:
        self.abort(AbortReason.COORDINATOR_KILL)
        self._set_state(AgentState.RETIRED)
        self._mailbox.unregister(self.agent_id)

    # -- Peer-to-Peer --

    def send_to_peer(self, target_role: AgentRoleType, subject: str,
                     payload: dict[str, Any]) -> bool:
        target_prefix = f"{target_role.value}-"
        for aid in list(self._mailbox._inboxes.keys()):
            if aid.startswith(target_prefix):
                return self._mailbox.send(AgentMessage(
                    msg_type=MessageType.PEER_REQUEST,
                    sender=self.agent_id, recipient=aid,
                    subject=subject, payload=payload,
                ))
        return False

    # -- E-GAP 2: Build Conflict Position --

    def build_conflict_position(self, topic: str,
                                context: dict[str, Any] | None = None) -> ConflictPosition:
        """E-GAP 2: Build a structured position for conflict resolution."""
        opinion = self.form_opinion(topic, context)
        # E-GAP 1: Weight confidence by learning profile calibration
        calibrated_confidence = (
            opinion.confidence * 0.6
            + self._learning_profile.success_rate * 0.3
            + self._learning_profile.confidence_calibration * 0.1
        )
        return ConflictPosition(
            agent_id=self.agent_id,
            role=self.role.value,
            claim=opinion.assessment,
            confidence=min(1.0, calibrated_confidence),
            evidence=opinion.evidence,
            evidence_strength=self._learning_profile.success_rate,
        )

    # -- Opinions and Confidence --

    def form_opinion(self, topic: str, context: dict[str, Any] | None = None) -> AgentOpinion:
        ctx = context or {}
        opinion = self._default_opinion(topic, ctx)
        self._opinions.append(opinion)

        if self._stats["tasks_completed"] > 0:
            success_rate = self._stats["tasks_completed"] / max(
                1, self._stats["tasks_completed"] + self._stats["tasks_failed"],
            )
            self._confidence = 0.3 + 0.7 * success_rate
        opinion.confidence = self._confidence
        return opinion

    def challenge(self, opinion: AgentOpinion) -> AgentOpinion:
        counter = self._default_opinion(f"counter:{opinion.assessment}", {})
        counter.dissent_from = opinion.agent_id

        if self._evaluate_dissent(opinion):
            counter.assessment = (
                f"DISSENT: {self.role.value} disagrees with {opinion.role} - {opinion.assessment}"
            )
            counter.confidence = min(1.0, self._confidence + 0.1)
        else:
            counter.assessment = (
                f"CONCUR: {self.role.value} agrees with {opinion.role} - {opinion.assessment}"
            )
            counter.confidence = max(0.1, self._confidence - 0.1)

        counter.recommendation = f"Based on {self.role.value} expertise"
        self._opinions.append(counter)
        return counter

    def _default_opinion(self, topic: str, context: dict[str, Any]) -> AgentOpinion:
        assessments = {
            AgentRoleType.RECON: f"From recon perspective: {topic} requires broader surface enumeration",
            AgentRoleType.EXPLOIT: f"From exploit perspective: {topic} needs proof-of-concept validation",
            AgentRoleType.STRATEGY: f"From strategy perspective: {topic} should be prioritized by risk/reward",
            AgentRoleType.MEMORY: f"From memory perspective: {topic} matches historical patterns",
            AgentRoleType.DEFENSE: f"From defense perspective: {topic} must account for detection risk",
        }
        return AgentOpinion(
            agent_id=self.agent_id, role=self.role.value,
            confidence=self._confidence,
            assessment=assessments.get(self.role, f"{self.role.value}: {topic}"),
            evidence=[f"Working memory keys: {list(self._working_memory.keys())}"],
            recommendation=f"{self.role.value} recommends further analysis",
        )

    def _evaluate_dissent(self, opinion: AgentOpinion) -> bool:
        tension_pairs = {
            ("recon", "defense"), ("defense", "recon"),
            ("exploit", "strategy"), ("strategy", "exploit"),
        }
        if (self.role.value, opinion.role) in tension_pairs:
            return True
        return abs(self._confidence - opinion.confidence) > self._dissent_threshold

    # -- Scoped Memory --

    def write_memory(self, key: str, value: Any, scope: str = "") -> None:
        s = scope or self.capabilities.memory_scope
        if s in self._memory_store:
            self._memory_store[s][key] = value

    def read_memory(self, key: str, scope: str = "") -> Any:
        s = scope or self.capabilities.memory_scope
        return self._memory_store.get(s, {}).get(key)

    def get_memory_snapshot(self) -> dict[str, Any]:
        return {scope: dict(data) for scope, data in self._memory_store.items()}

    # -- Serialization --

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "role": self.role.value,
            "role_name": self.role_def["name"],
            "state": self._state.value,
            "color": self.capabilities.color,
            "current_task": self._current_task.to_dict() if self._current_task else None,
            "task_history_count": len(self._task_history),
            "recent_tasks": [t.to_dict() for t in list(self._task_history)[-5:]],
            "stats": self._stats,
            "confidence": self._confidence,
            "turn_count": self._turn_count,
            "max_turns": self.capabilities.max_turns,
            "timeout_s": self.capabilities.timeout_s,
            "memory_scope": self.capabilities.memory_scope,
            "memory_keys": {s: list(d.keys()) for s, d in self._memory_store.items()},
            "opinions": [o.to_dict() for o in list(self._opinions)[-5:]],
            "working_memory_keys": list(self._working_memory.keys()),
            "permission_mode": self._effective_permission.name,
            "usage": self._usage.to_dict(),
            "learning_profile": self._learning_profile.to_dict(),
            "last_brief": self._last_brief.to_dict() if self._last_brief else None,
            "capabilities": {
                "allowed_tools": self.capabilities.allowed_tools[:10],
                "max_parallel_tasks": self.capabilities.max_parallel_tasks,
                "read_only": self.capabilities.read_only,
                "execution_mode": self.capabilities.execution_mode.value,
                "can_spawn_subagents": self.capabilities.can_spawn_subagents,
            },
        }


# ===================================================================
# AGENT COORDINATOR
# ===================================================================


class AgentCoordinator:
    """Central orchestrator with E-GAP 1-5 emergent intelligence systems.

    E-GAP 1: Agent Identity Evolution -- per-agent learning profiles with
              fitness-based task selection.
    E-GAP 2: Conflict Resolution Engine -- structured multi-round disagreement
              resolution with evidence weighting.
    E-GAP 3: Pre-Decision Memory Injection -- memory recall briefs compiled and
              injected into agents BEFORE they execute tasks.
    E-GAP 4: Simulation Layer -- predict-before-execute with expected value
              scoring across candidate actions.
    E-GAP 5: Emergent Strategy Formation -- multi-phase strategic arcs that
              evolve based on intermediate results with pivot capability.
    """

    TENSION_PAIRS: list[tuple[AgentRoleType, AgentRoleType]] = [
        (AgentRoleType.RECON, AgentRoleType.DEFENSE),
        (AgentRoleType.EXPLOIT, AgentRoleType.STRATEGY),
        (AgentRoleType.STRATEGY, AgentRoleType.MEMORY),
    ]

    def __init__(
        self,
        on_event: Callable[[dict[str, Any]], None] | None = None,
        execute_fns: dict[str, Callable[..., dict[str, Any]]] | None = None,
    ) -> None:
        self._on_event = on_event
        self._shared_context = SharedContext()
        self._mailbox = AgentMailbox()

        # E-GAP 3: Shared memory index
        self._memory_index = MemoryIndex()

        self._mailbox.register("coordinator")
        self._mailbox.subscribe("coordinator", self._on_coordinator_message)

        fns = execute_fns or {}
        self._agents: dict[AgentRoleType, SpecialistAgent] = {}
        for role_type in AgentRoleType:
            agent = SpecialistAgent(
                role=role_type,
                shared_context=self._shared_context,
                mailbox=self._mailbox,
                memory_index=self._memory_index,
                execute_fn=fns.get(role_type.value),
                on_state_change=self._on_agent_state_change,
            )
            self._agents[role_type] = agent

        self._pending_results: dict[str, TaskAssignment] = {}
        self._completed_tasks: deque[TaskAssignment] = deque(maxlen=200)
        self._cycle_count = 0

        # Dispatch history
        self._dispatch_history: deque[DispatchRecord] = deque(maxlen=200)
        self._notifications: deque[TaskNotification] = deque(maxlen=100)

        # Deliberation
        self._deliberation_log: deque[DeliberationRound] = deque(maxlen=50)

        # Active memory
        self._memory_injections: list[MemoryInjection] = []
        self._playbook_suggestions: list[PlaybookSuggestion] = []

        # Strategic planning
        self._strategic_plans: list[StrategicPlan] = []
        self._current_plan: StrategicPlan | None = None

        # Emergent behavior
        self._emergent_insights: list[dict[str, Any]] = []
        self._feedback_loops: dict[str, dict[str, Any]] = {}

        self._agent_weights: dict[str, float] = {
            "recon": 1.0, "exploit": 1.2, "strategy": 1.1,
            "memory": 0.8, "defense": 1.0,
        }

        # ── E-GAP 2: Conflict resolution log ──
        self._conflict_resolutions: deque[ConflictResolution] = deque(maxlen=50)

        # ── E-GAP 4: Simulation log ──
        self._simulation_results: deque[SimulationResult] = deque(maxlen=50)

        # ── E-GAP 5: Strategic arcs ──
        self._strategic_arcs: list[StrategicArc] = []
        self._current_arc: StrategicArc | None = None

    # -- Properties --

    @property
    def shared_context(self) -> SharedContext:
        return self._shared_context

    @property
    def mailbox(self) -> AgentMailbox:
        return self._mailbox

    @property
    def memory_index(self) -> MemoryIndex:
        """E-GAP 3: Access the shared memory index."""
        return self._memory_index

    def get_agent(self, role: AgentRoleType) -> SpecialistAgent:
        return self._agents[role]

    def get_all_agents(self) -> dict[AgentRoleType, SpecialistAgent]:
        return dict(self._agents)

    # -- Context Overlap (Spawn-vs-Continue) --

    def _compute_context_overlap(self, role: AgentRoleType,
                                 new_context: dict[str, Any]) -> float:
        agent = self._agents[role]
        if not agent._task_history:
            return 0.0

        last_task = agent._task_history[-1]
        internal_keys = {"_allowed_tools", "_disallowed_tools", "_read_only",
                         "_permission_mode", "_pre_decision_brief",
                         "_agent_fitness", "_agent_success_rate"}
        last_context_keys = set(last_task.context.keys()) - internal_keys
        new_context_keys = set(new_context.keys()) - internal_keys

        if not last_context_keys and not new_context_keys:
            return 0.5

        union = last_context_keys | new_context_keys
        intersection = last_context_keys & new_context_keys
        if not union:
            return 0.5

        key_overlap = len(intersection) / len(union)
        agent_produces = set(agent.role_def.get("produces", []))
        active_keys = set(self._shared_context.active_keys())
        data_coverage = len(agent_produces & active_keys) / max(1, len(agent_produces))

        return 0.6 * key_overlap + 0.4 * data_coverage

    def dispatch_or_continue(
        self, role: AgentRoleType, description: str,
        instructions: str = "", context: dict[str, Any] | None = None,
        overlap_threshold: float = 0.6,
    ) -> tuple[TaskAssignment, str]:
        ctx = context or {}
        overlap = self._compute_context_overlap(role, ctx)
        agent = self._agents[role]

        if overlap >= overlap_threshold and agent.state in (AgentState.COMPLETED, AgentState.IDLE):
            decision = "continue"
        else:
            decision = "fresh"
            agent._working_memory.clear()

        task = self.dispatch_task(role, description, instructions, ctx)
        self._emit_event({
            "type": "dispatch_decision", "role": role.value,
            "decision": decision, "overlap": round(overlap, 3),
            "task_id": task.task_id,
        })
        return task, decision

    # -- Core Dispatch --

    def dispatch_task(
        self, role: AgentRoleType, description: str,
        instructions: str = "", context: dict[str, Any] | None = None,
    ) -> TaskAssignment:
        prefix = TASK_ID_PREFIXES.get(role.value, "t-")
        task = TaskAssignment(
            task_id=f"{prefix}{uuid.uuid4().hex[:8]}",
            description=description, instructions=instructions,
            assigned_to=role.value, context=context or {},
        )

        caps = self._agents[role].capabilities
        task.context["_visible_tools"] = caps.allowed_tools
        task.context["_role"] = role.value
        task.context["_max_turns"] = caps.max_turns
        task.context["_timeout_s"] = caps.timeout_s

        # ── E-GAP 3: Compile pre-decision brief ──
        brief = self._compile_pre_decision_brief(role, description, task.context)
        self._agents[role]._last_brief = brief

        self._pending_results[task.task_id] = task
        self._agents[role].assign_task(task)

        record = DispatchRecord(
            task_id=task.task_id, role=role.value,
            description=description,
            context_keys=list((context or {}).keys()),
        )
        self._dispatch_history.append(record)

        self._emit_event({
            "type": "agent_task_dispatched", "role": role.value,
            "task_id": task.task_id, "description": description,
        })
        return task

    def dispatch_parallel(
        self, tasks: list[tuple[AgentRoleType, str, str, dict[str, Any] | None]],
    ) -> list[TaskAssignment]:
        results = []
        for role, desc, instr, ctx in tasks:
            results.append(self.dispatch_task(role, desc, instr, ctx))
        return results

    # -- E-GAP 1: Fitness-Based Agent Selection --

    def select_best_agent_for_task(
        self,
        candidate_roles: list[AgentRoleType],
        required_tools: list[str] | None = None,
        required_techniques: list[str] | None = None,
    ) -> AgentRoleType:
        """E-GAP 1: Select the best agent for a task based on learning profiles."""
        best_role = candidate_roles[0]
        best_fitness = -1.0

        for role in candidate_roles:
            agent = self._agents[role]
            if agent.state == AgentState.RETIRED:
                continue
            fitness = agent.learning_profile.fitness_for_task(
                required_tools=required_tools,
                required_techniques=required_techniques,
            )
            # Bonus for idle agents (prefer not to interrupt running agents)
            if agent.state == AgentState.IDLE:
                fitness += 0.05
            if fitness > best_fitness:
                best_fitness = fitness
                best_role = role

        self._emit_event({
            "type": "agent_selection",
            "selected": best_role.value,
            "fitness": round(best_fitness, 3),
            "candidates": [r.value for r in candidate_roles],
        })
        return best_role

    def get_agent_rankings(self) -> list[dict[str, Any]]:
        """E-GAP 1: Get agents ranked by overall fitness."""
        rankings = []
        for role, agent in self._agents.items():
            lp = agent.learning_profile
            rankings.append({
                "role": role.value,
                "fitness": round(lp.fitness_for_task(), 3),
                "success_rate": round(lp.success_rate, 3),
                "specialization": round(lp.specialization_score, 3),
                "tasks_attempted": lp.tasks_attempted,
                "streak": lp.streak,
                "best_streak": lp.best_streak,
                "top_tools": dict(sorted(
                    lp.tool_mastery.items(), key=lambda x: -x[1],
                )[:5]),
                "top_techniques": dict(sorted(
                    lp.technique_affinity.items(), key=lambda x: -x[1],
                )[:5]),
            })
        rankings.sort(key=lambda x: -x["fitness"])
        return rankings

    # -- E-GAP 2: Structured Conflict Resolution Engine --

    def resolve_conflict(
        self,
        topic: str,
        participant_roles: list[AgentRoleType] | None = None,
        max_rounds: int = 3,
    ) -> ConflictResolution:
        """E-GAP 2: Run structured disagreement resolution.

        Process:
        1. Each participant builds a ConflictPosition
        2. Positions are scored by confidence * evidence_strength * agent_weight
        3. If margin < threshold, enter rebuttal round
        4. If still no resolution after max_rounds, escalate
        """
        participants = participant_roles or list(AgentRoleType)
        positions: list[ConflictPosition] = []

        for role in participants:
            agent = self._agents[role]
            if agent.state != AgentState.RETIRED:
                pos = agent.build_conflict_position(topic)
                positions.append(pos)

        if len(positions) < 2:
            resolution = ConflictResolution(
                topic=topic, positions=positions,
                method=ConflictResolutionMethod.UNANIMOUS,
                winner=positions[0].role if positions else "",
                winning_claim=positions[0].claim if positions else "",
                margin=1.0, rationale="Single position -- no conflict",
            )
            self._conflict_resolutions.append(resolution)
            return resolution

        # Score each position
        scored: list[tuple[float, ConflictPosition]] = []
        for pos in positions:
            weight = self._agent_weights.get(pos.role, 1.0)
            score = pos.confidence * pos.evidence_strength * weight
            scored.append((score, pos))

        scored.sort(key=lambda x: -x[0])
        current_round = 1
        method = ConflictResolutionMethod.WEIGHTED_VOTE

        while current_round <= max_rounds:
            top_score, top_pos = scored[0]
            second_score = scored[1][0] if len(scored) > 1 else 0.0
            margin = top_score - second_score

            if margin > 0.2 or current_round == max_rounds:
                break

            # Rebuttal round: second-place challenges first-place
            challenger_agent = self._agents.get(AgentRoleType(scored[1][1].role))
            if challenger_agent:
                counter = challenger_agent.challenge(
                    AgentOpinion(
                        agent_id=top_pos.agent_id, role=top_pos.role,
                        confidence=top_pos.confidence,
                        assessment=top_pos.claim,
                    )
                )
                # Adjust scores after rebuttal
                if "DISSENT" in counter.assessment:
                    scored[1] = (scored[1][0] + 0.1, scored[1][1])
                    method = ConflictResolutionMethod.EVIDENCE_STRENGTH
                else:
                    scored[0] = (scored[0][0] + 0.05, scored[0][1])

            scored.sort(key=lambda x: -x[0])
            current_round += 1

        top_score, winner_pos = scored[0]
        second_score = scored[1][0] if len(scored) > 1 else 0.0
        final_margin = top_score - second_score

        escalated = current_round > max_rounds and final_margin < 0.1

        resolution = ConflictResolution(
            topic=topic, positions=positions,
            method=method,
            winner=winner_pos.role,
            winning_claim=winner_pos.claim,
            margin=final_margin,
            rounds_taken=current_round,
            escalated=escalated,
            rationale=(
                f"{winner_pos.role} prevails with score {top_score:.3f} "
                f"(margin {final_margin:.3f}) after {current_round} round(s)"
            ),
        )

        self._conflict_resolutions.append(resolution)
        self._emit_event({
            "type": "conflict_resolved",
            "resolution": resolution.to_dict(),
        })

        # E-GAP 1: Update confidence calibration for participants
        for pos in positions:
            try:
                agent = self._agents[AgentRoleType(pos.role)]
                if pos.role == winner_pos.role:
                    agent._learning_profile.confidence_calibration = _ema(
                        agent._learning_profile.confidence_calibration, 1.0, 0.2,
                    )
                else:
                    agent._learning_profile.confidence_calibration = _ema(
                        agent._learning_profile.confidence_calibration, 0.3, 0.2,
                    )
            except (ValueError, KeyError):
                pass

        return resolution

    def get_conflict_history(self) -> list[dict[str, Any]]:
        """E-GAP 2: Get conflict resolution history."""
        return [r.to_dict() for r in self._conflict_resolutions]

    # -- E-GAP 3: Pre-Decision Memory Injection --

    def _compile_pre_decision_brief(
        self, role: AgentRoleType, task_description: str,
        context: dict[str, Any],
    ) -> PreDecisionBrief:
        """E-GAP 3: Compile a pre-decision brief by recalling relevant memories.

        Modeled after Anthropic\\'s buildMemoryPrompt() + findRelevantMemories()
        but adapted for pentesting context: recalls technique outcomes, platform
        patterns, and past failures to shape agent behavior BEFORE execution.
        """
        target = context.get("target_url", "")
        query_terms = [task_description, target, role.value]

        # Pull technique outcomes
        technique_memories = self._memory_index.recall(
            query_terms=query_terms,
            category="technique_success",
            max_results=3,
        )
        failure_memories = self._memory_index.recall(
            query_terms=query_terms,
            category="technique_failure",
            max_results=3,
        )
        platform_memories = self._memory_index.recall(
            query_terms=query_terms,
            category="platform_pattern",
            max_results=2,
        )

        all_recalled = technique_memories + failure_memories + platform_memories

        # Build suppressions from repeated failures
        suppressions: list[str] = []
        for mem in failure_memories:
            if mem.times_recalled >= 2:
                suppressions.append(
                    f"SUPPRESS: {mem.content[:100]} (failed {mem.times_recalled} times)"
                )

        # Build recommendations from successes
        recommendations: list[str] = []
        for mem in technique_memories:
            recommendations.append(
                f"RECOMMEND: {mem.content[:100]} (relevance {mem.relevance_score:.2f})"
            )

        brief = PreDecisionBrief(
            target_role=role.value,
            task_description=task_description,
            recalled_memories=all_recalled,
            suppressions=suppressions,
            recommendations=recommendations,
            confidence=min(1.0, len(all_recalled) * 0.15 + 0.3),
        )

        self._emit_event({
            "type": "pre_decision_brief",
            "role": role.value,
            "recalled_count": len(all_recalled),
            "suppressions": len(suppressions),
            "recommendations": len(recommendations),
        })

        return brief

    def store_memory(self, category: str, content: str, source_agent: str = "",
                     target: str = "", relevance: float = 0.5) -> dict[str, Any]:
        """E-GAP 3: Public API to store a memory entry."""
        entry = self._memory_index.store(
            category=category, content=content,
            source_agent=source_agent, target=target,
            relevance=relevance,
        )
        return entry.to_dict()

    def recall_memories(self, query_terms: list[str], category: str = "",
                        max_results: int = 5) -> list[dict[str, Any]]:
        """E-GAP 3: Public API to recall memories."""
        entries = self._memory_index.recall(
            query_terms=query_terms, category=category,
            max_results=max_results,
        )
        return [e.to_dict() for e in entries]

    # -- E-GAP 4: Simulation / Prediction Layer --

    def simulate_actions(
        self, candidate_actions: list[dict[str, Any]],
    ) -> SimulationResult:
        """E-GAP 4: Simulate candidate actions and rank by expected value.

        Each candidate_action dict:
          - action: str (description)
          - role: str (which agent would execute)
          - tools: list[str] (tools needed)
          - techniques: list[str] (attack techniques)
          - detection_risk: float (0-1, optional)

        Uses agent learning profiles + memory index to predict outcomes.
        """
        scenarios: list[SimulationScenario] = []

        for action_spec in candidate_actions:
            action_name = action_spec.get("action", "unknown")
            role_name = action_spec.get("role", "exploit")
            tools = action_spec.get("tools", [])
            techniques = action_spec.get("techniques", [])
            detection_risk = action_spec.get("detection_risk", 0.3)

            # Predict success probability from agent fitness
            try:
                role = AgentRoleType(role_name)
                agent = self._agents[role]
                fitness = agent.learning_profile.fitness_for_task(
                    required_tools=tools,
                    required_techniques=techniques,
                )
            except (ValueError, KeyError):
                fitness = 0.5

            # Predict findings count from memory index
            memories = self._memory_index.recall(
                query_terms=techniques + tools,
                category="technique_success",
                max_results=5,
            )
            historical_success_count = len(memories)

            predicted_findings = max(1, int(historical_success_count * fitness * 3))
            predicted_duration = 60.0 + (1.0 - fitness) * 240.0

            # Check failure memories
            failure_memories = self._memory_index.recall(
                query_terms=techniques + tools,
                category="technique_failure",
                max_results=5,
            )
            failure_penalty = len(failure_memories) * 0.1

            scenario = SimulationScenario(
                action=action_name,
                predicted_findings=predicted_findings,
                predicted_duration_s=predicted_duration,
                detection_risk=detection_risk,
                success_probability=max(0.05, fitness - failure_penalty),
                resource_cost=detection_risk * 0.5 + predicted_duration / 600.0,
            )
            scenario.compute_expected_value()
            scenarios.append(scenario)

        # Rank by expected value
        scenarios.sort(key=lambda s: -s.expected_value)

        recommended = scenarios[0] if scenarios else None
        result = SimulationResult(
            scenarios=scenarios,
            recommended_action=recommended.action if recommended else "",
            recommendation_reason=(
                f"Highest EV={recommended.expected_value:.3f}, "
                f"P(success)={recommended.success_probability:.3f}"
                if recommended else "No scenarios"
            ),
            confidence=recommended.success_probability if recommended else 0.0,
        )

        self._simulation_results.append(result)
        self._emit_event({
            "type": "simulation_completed",
            "scenarios_count": len(scenarios),
            "recommended": result.recommended_action,
        })
        return result

    def get_simulation_history(self) -> list[dict[str, Any]]:
        """E-GAP 4: Get simulation result history."""
        return [r.to_dict() for r in self._simulation_results]

    # -- E-GAP 5: Emergent Multi-Step Strategy Formation --

    def start_strategic_arc(self, objective: str, target_url: str = "") -> StrategicArc:
        """E-GAP 5: Begin a new multi-phase strategic arc."""
        arc = StrategicArc(objective=objective)
        arc.confidence_trajectory.append(0.5)

        # Start with reconnaissance phase
        arc.advance_phase(StrategyArcPhase.RECONNAISSANCE, "Arc initiated")

        self._strategic_arcs.append(arc)
        self._current_arc = arc

        self._emit_event({
            "type": "strategic_arc_started",
            "arc_id": arc.arc_id,
            "objective": objective,
        })
        return arc

    def advance_arc_phase(
        self,
        outcome: dict[str, Any] | None = None,
        force_phase: StrategyArcPhase | None = None,
    ) -> StrategicArc | None:
        """E-GAP 5: Advance the current strategic arc to the next phase.

        Automatically determines the next phase based on current phase and
        outcomes, or accepts a forced phase transition.
        """
        arc = self._current_arc
        if not arc or arc.status != "active":
            return None

        current = arc.current_phase
        outcome = outcome or {}

        # Record findings from this phase
        phase_findings = outcome.get("findings", [])
        for f in phase_findings:
            arc.accumulated_findings.append(str(f)[:200])

        # Update confidence trajectory
        phase_confidence = outcome.get("confidence", 0.5)
        arc.confidence_trajectory.append(phase_confidence)

        # ── Determine next phase ──
        if force_phase:
            next_phase = force_phase
            reason = f"Forced transition to {force_phase.value}"
        else:
            next_phase, reason = self._determine_next_phase(arc, current, outcome)

        # Check for pivot conditions
        if self._should_pivot(arc, outcome):
            pivot_reason = outcome.get("pivot_reason", "Diminishing returns detected")
            if arc.record_pivot(pivot_reason):
                self._emit_event({
                    "type": "strategic_arc_pivot",
                    "arc_id": arc.arc_id,
                    "pivot_count": arc.pivot_count,
                    "reason": pivot_reason,
                })
                return arc

        arc.advance_phase(next_phase, reason, outcome)

        # Check for arc completion
        if next_phase == StrategyArcPhase.CONSOLIDATION:
            arc.decisions_made.append({
                "type": "entering_consolidation",
                "total_findings": len(arc.accumulated_findings),
                "timestamp": time.time(),
            })

        self._emit_event({
            "type": "strategic_arc_advanced",
            "arc_id": arc.arc_id,
            "new_phase": next_phase.value,
            "reason": reason,
        })
        return arc

    def complete_arc(self, final_outcome: dict[str, Any] | None = None) -> StrategicArc | None:
        """E-GAP 5: Complete the current strategic arc."""
        arc = self._current_arc
        if not arc:
            return None
        arc.complete(final_outcome)
        self._emit_event({
            "type": "strategic_arc_completed",
            "arc_id": arc.arc_id,
            "phases_traversed": len(arc.phase_history),
            "pivots": arc.pivot_count,
            "findings": len(arc.accumulated_findings),
        })
        return arc

    def _determine_next_phase(
        self, arc: StrategicArc, current: StrategyArcPhase,
        outcome: dict[str, Any],
    ) -> tuple[StrategyArcPhase, str]:
        """E-GAP 5: Intelligent phase transition logic."""
        findings_count = len(outcome.get("findings", []))
        endpoints_found = outcome.get("endpoints_found", 0)
        confidence = outcome.get("confidence", 0.5)

        phase_flow: dict[StrategyArcPhase, StrategyArcPhase] = {
            StrategyArcPhase.RECONNAISSANCE: StrategyArcPhase.ANALYSIS,
            StrategyArcPhase.ANALYSIS: StrategyArcPhase.EXPLOITATION,
            StrategyArcPhase.EXPLOITATION: StrategyArcPhase.VERIFICATION,
            StrategyArcPhase.VERIFICATION: StrategyArcPhase.CONSOLIDATION,
            StrategyArcPhase.CONSOLIDATION: StrategyArcPhase.CONSOLIDATION,
            StrategyArcPhase.PIVOT: StrategyArcPhase.RECONNAISSANCE,
        }

        default_next = phase_flow.get(current, StrategyArcPhase.CONSOLIDATION)

        # Adaptive transitions
        if current == StrategyArcPhase.RECONNAISSANCE and endpoints_found == 0:
            return StrategyArcPhase.RECONNAISSANCE, "No endpoints found -- re-running recon"

        if current == StrategyArcPhase.EXPLOITATION and findings_count == 0 and confidence < 0.3:
            return StrategyArcPhase.ANALYSIS, "Exploitation yielded nothing -- back to analysis"

        if current == StrategyArcPhase.VERIFICATION and confidence > 0.8:
            return StrategyArcPhase.CONSOLIDATION, "High confidence verification -- finalizing"

        return default_next, f"Standard flow from {current.value}"

    def _should_pivot(self, arc: StrategicArc, outcome: dict[str, Any]) -> bool:
        """E-GAP 5: Detect when the arc should pivot strategy."""
        if arc.pivot_count >= arc.max_pivots:
            return False

        # Pivot if consecutive low-confidence phases
        if len(arc.confidence_trajectory) >= 3:
            recent = arc.confidence_trajectory[-3:]
            if all(c < 0.3 for c in recent):
                return True

        # Pivot if explicit signal
        if outcome.get("should_pivot", False):
            return True

        return False

    def get_current_arc(self) -> dict[str, Any] | None:
        """E-GAP 5: Get the current strategic arc state."""
        if self._current_arc:
            return self._current_arc.to_dict()
        return None

    def get_arc_history(self) -> list[dict[str, Any]]:
        """E-GAP 5: Get all strategic arc history."""
        return [a.to_dict() for a in self._strategic_arcs]

    # -- Cycle --

    def run_cycle(
        self, target_url: str = "", beliefs: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        self._cycle_count += 1
        cycle_start = time.time()
        cycle_context = {
            "target_url": target_url,
            "beliefs": beliefs or {},
            "cycle": self._cycle_count,
        }

        self.dispatch_task(AgentRoleType.DEFENSE, "Assess defense posture", "", cycle_context)
        self.dispatch_task(AgentRoleType.RECON, "Run reconnaissance", "", cycle_context)
        self._wait_for_agents([AgentRoleType.DEFENSE, AgentRoleType.RECON], timeout=60)

        self.dispatch_task(AgentRoleType.STRATEGY, "Plan attack strategy", "", cycle_context)
        self._wait_for_agents([AgentRoleType.STRATEGY], timeout=30)

        self.dispatch_task(AgentRoleType.EXPLOIT, "Execute exploitation", "", cycle_context)
        self._wait_for_agents([AgentRoleType.EXPLOIT], timeout=120)

        self.dispatch_task(AgentRoleType.MEMORY, "Consolidate findings", "", cycle_context)
        self._wait_for_agents([AgentRoleType.MEMORY], timeout=30)

        return {
            "cycle": self._cycle_count,
            "duration_s": time.time() - cycle_start,
            "shared_context": self._shared_context.to_dict(),
            "usage": self.get_aggregate_usage(),
        }

    def _wait_for_agents(self, roles: list[AgentRoleType], timeout: float = 60) -> None:
        deadline = time.time() + timeout
        while time.time() < deadline:
            all_done = True
            for role in roles:
                if self._agents[role].state == AgentState.RUNNING:
                    all_done = False
                    break
            if all_done:
                return
            time.sleep(0.5)
        for role in roles:
            if self._agents[role].state == AgentState.RUNNING:
                logger.warning("Agent %s still running after timeout", role.value)

    # -- Communication --

    def broadcast(self, msg_type: MessageType, subject: str,
                  payload: dict[str, Any]) -> None:
        self._mailbox.send(AgentMessage(
            msg_type=msg_type, sender="coordinator",
            recipient="*", subject=subject, payload=payload,
        ))

    def send_to_agent(self, role: AgentRoleType, msg_type: MessageType,
                      subject: str, payload: dict[str, Any]) -> bool:
        agent = self._agents.get(role)
        if not agent:
            return False
        return self._mailbox.send(AgentMessage(
            msg_type=msg_type, sender="coordinator",
            recipient=agent.agent_id, subject=subject, payload=payload,
        ))

    # -- Lifecycle --

    def get_agent_states(self) -> dict[str, str]:
        return {r.value: a.state.value for r, a in self._agents.items()}

    def pause_agent(self, role: AgentRoleType) -> bool:
        agent = self._agents.get(role)
        if agent and agent.state in (AgentState.IDLE, AgentState.RUNNING, AgentState.COMPLETED):
            agent._set_state(AgentState.PAUSED)
            return True
        return False

    def resume_agent(self, role: AgentRoleType) -> bool:
        agent = self._agents.get(role)
        if agent and agent.state == AgentState.PAUSED:
            agent._set_state(AgentState.IDLE)
            return True
        return False

    def abort_agent(self, role: AgentRoleType,
                    reason: AbortReason = AbortReason.COORDINATOR_KILL) -> bool:
        agent = self._agents.get(role)
        if agent:
            return agent.abort(reason)
        return False

    def get_agent_memory(self, role: AgentRoleType) -> dict[str, Any]:
        agent = self._agents.get(role)
        if agent:
            return agent.get_memory_snapshot()
        return {}

    def replace_execute_fn(self, role: AgentRoleType,
                           fn: Callable[..., dict[str, Any]]) -> None:
        agent = self._agents.get(role)
        if agent:
            agent._execute_fn = fn

    # -- Usage --

    def get_aggregate_usage(self) -> dict[str, Any]:
        total = UsageTracker()
        per_agent: dict[str, dict[str, Any]] = {}
        for role, agent in self._agents.items():
            u = agent.usage
            total.tasks_run += u.tasks_run
            total.total_wall_time_s += u.total_wall_time_s
            total.tool_invocations += u.tool_invocations
            total.findings_produced += u.findings_produced
            total.errors_encountered += u.errors_encountered
            per_agent[role.value] = u.to_dict()
        return {"total": total.to_dict(), "per_agent": per_agent}

    # -- Permission Escalation --

    def escalate_permission(self, role: AgentRoleType, mode: PermissionMode) -> None:
        agent = self._agents.get(role)
        if agent:
            agent.set_permission_mode(mode)
            self._emit_event({
                "type": "permission_escalation",
                "role": role.value, "new_mode": mode.name,
            })

    # -- Opinions --

    def collect_opinions(self, topic: str = "Current assessment") -> dict[str, AgentOpinion]:
        opinions: dict[str, AgentOpinion] = {}
        for role, agent in self._agents.items():
            if agent.state != AgentState.RETIRED:
                opinions[role.value] = agent.form_opinion(topic)
        return opinions

    def resolve_disagreements(self) -> dict[str, Any]:
        opinions = self.collect_opinions()
        if not opinions:
            return {"resolution": "no_opinions", "winner": ""}

        weighted: dict[str, float] = {}
        for role, opinion in opinions.items():
            weight = self._agent_weights.get(role, 1.0)
            weighted[role] = opinion.confidence * weight

        winner_role = max(weighted, key=weighted.get)  # type: ignore[arg-type]
        winner_opinion = opinions[winner_role]

        return {
            "resolution": "weighted_vote",
            "winner": winner_role,
            "winning_opinion": winner_opinion.to_dict(),
            "scores": weighted,
            "all_opinions": {r: o.to_dict() for r, o in opinions.items()},
        }

    # -- Adversarial Deliberation --

    def run_deliberation(
        self, challenger_role: AgentRoleType,
        defender_role: AgentRoleType,
        topic: str = "Adversarial review",
    ) -> DeliberationRound:
        challenger = self._agents[challenger_role]
        defender = self._agents[defender_role]

        c_opinion = challenger.form_opinion(topic)
        d_opinion = defender.challenge(c_opinion)

        c_score = c_opinion.confidence * self._agent_weights.get(challenger_role.value, 1.0)
        d_score = d_opinion.confidence * self._agent_weights.get(defender_role.value, 1.0)
        winner = challenger_role.value if c_score >= d_score else defender_role.value

        rnd = DeliberationRound(
            challenger=challenger_role.value,
            defender=defender_role.value, topic=topic,
            challenger_opinion=c_opinion, defender_opinion=d_opinion,
            resolution=f"{winner} prevails ({c_score:.2f} vs {d_score:.2f})",
            winner=winner,
        )
        self._deliberation_log.append(rnd)
        self._emit_event({"type": "deliberation_round", "round": rnd.to_dict()})
        return rnd

    def run_all_tensions(self) -> list[DeliberationRound]:
        rounds = []
        for challenger, defender in self.TENSION_PAIRS:
            rounds.append(self.run_deliberation(challenger, defender))
        return rounds

    # -- Active Memory --

    def inject_memory_pattern(
        self, pattern_type: str, content: str,
        confidence: float = 0.5, roles: list[str] | None = None,
        override_strength: float = 0.0,
    ) -> MemoryInjection:
        target_roles = roles or [r.value for r in AgentRoleType]
        injection = MemoryInjection(
            pattern_type=pattern_type, content=content,
            confidence=confidence, target_roles=target_roles,
            override_strength=override_strength,
        )
        self._memory_injections.append(injection)

        for role_name in target_roles:
            try:
                role = AgentRoleType(role_name)
                agent = self._agents.get(role)
                if agent:
                    agent.write_memory(f"injection_{injection.injection_id}", {
                        "type": pattern_type, "content": content,
                        "confidence": confidence, "override": override_strength,
                    })
            except ValueError:
                pass

        # E-GAP 3: Also store in memory index for future recall
        self._memory_index.store(
            category="injected_pattern", content=content,
            relevance=confidence,
        )

        self._emit_event({"type": "memory_injection", "injection": injection.to_dict()})
        return injection

    def suggest_playbook(
        self, name: str, description: str, steps: list[str],
        success_rate: float = 0.0, confidence: float = 0.5,
    ) -> PlaybookSuggestion:
        suggestion = PlaybookSuggestion(
            name=name, description=description, steps=steps,
            success_rate=success_rate, confidence=confidence,
        )
        self._playbook_suggestions.append(suggestion)
        self._emit_event({"type": "playbook_suggestion", "suggestion": suggestion.to_dict()})
        return suggestion

    # -- Strategic Planning --

    def build_strategic_plan(self, objective: str = "") -> StrategicPlan:
        plan = StrategicPlan(
            objective=objective or "Maximum vulnerability coverage",
            phases=[
                {"name": "reconnaissance", "priority": 1, "estimated_duration_s": 120},
                {"name": "defense_assessment", "priority": 0, "estimated_duration_s": 60},
                {"name": "strategy_formulation", "priority": 2, "estimated_duration_s": 30},
                {"name": "exploitation", "priority": 3, "estimated_duration_s": 300},
                {"name": "consolidation", "priority": 5, "estimated_duration_s": 60},
            ],
            agent_assignments={
                "reconnaissance": ["recon"],
                "defense_assessment": ["defense"],
                "strategy_formulation": ["strategy"],
                "exploitation": ["exploit"],
                "consolidation": ["memory"],
            },
            estimated_duration_s=570.0, confidence=0.6, status="active",
        )
        self._strategic_plans.append(plan)
        self._current_plan = plan
        self._emit_event({"type": "strategic_plan", "plan": plan.to_dict()})
        return plan

    def get_current_plan(self) -> StrategicPlan | None:
        return self._current_plan

    def simulate_outcome(self, plan: StrategicPlan) -> dict[str, Any]:
        estimates: list[dict[str, Any]] = []
        for phase in plan.phases:
            estimates.append({
                "phase": phase["name"],
                "expected_findings": max(1, int(5 * plan.confidence)),
                "estimated_time_s": phase.get("estimated_duration_s", 60),
                "risk": 0.2 if phase["name"] in ("reconnaissance", "consolidation") else 0.5,
            })
        return {
            "plan_id": plan.plan_id,
            "phase_estimates": estimates,
            "overall_confidence": plan.confidence,
            "total_estimated_time_s": plan.estimated_duration_s,
        }

    # -- Emergent Behavior --

    def detect_emergent_behavior(self) -> list[dict[str, Any]]:
        insights: list[dict[str, Any]] = []

        opinions = self.collect_opinions("Emergent pattern check")
        if opinions:
            confidences = [o.confidence for o in opinions.values()]
            avg_conf = sum(confidences) / len(confidences)
            if avg_conf > 0.7:
                insight = {
                    "type": "confidence_convergence",
                    "description": "All agents showing high confidence",
                    "avg_confidence": avg_conf,
                    "timestamp": time.time(),
                }
                insights.append(insight)
                self._emergent_insights.append(insight)

            for role, opinion in opinions.items():
                dissent_count = sum(
                    1 for other in opinions.values()
                    if other.role != role and abs(other.confidence - opinion.confidence) > 0.3
                )
                if dissent_count >= 3:
                    insight = {
                        "type": "majority_dissent",
                        "description": f"Majority dissent against {role}",
                        "target_role": role, "dissent_count": dissent_count,
                        "timestamp": time.time(),
                    }
                    insights.append(insight)
                    self._emergent_insights.append(insight)

        loop_insights = self._check_feedback_loops()
        insights.extend(loop_insights)
        return insights

    def register_feedback_loop(
        self, name: str, source_role: str, target_role: str,
        transform_fn: Callable[[Any], Any] | None = None,
    ) -> None:
        self._feedback_loops[name] = {
            "source": source_role, "target": target_role,
            "transform": transform_fn,
            "activations": 0, "last_activated": 0.0,
        }

    def _check_feedback_loops(self) -> list[dict[str, Any]]:
        insights: list[dict[str, Any]] = []
        for name, loop in self._feedback_loops.items():
            src_role = loop["source"]
            tgt_role = loop["target"]
            try:
                src = self._agents[AgentRoleType(src_role)]
                tgt = self._agents[AgentRoleType(tgt_role)]
            except (ValueError, KeyError):
                continue

            if src._opinions:
                latest = src._opinions[-1]
                transform = loop.get("transform")
                if transform:
                    try:
                        transformed = transform(latest)
                        tgt._working_memory[f"feedback_{name}"] = transformed
                    except Exception:
                        pass
                else:
                    tgt._working_memory[f"feedback_{name}"] = latest.to_dict()

                loop["activations"] += 1
                loop["last_activated"] = time.time()

                if loop["activations"] % 10 == 0:
                    insight = {
                        "type": "feedback_loop_milestone",
                        "loop_name": name,
                        "activations": loop["activations"],
                        "source": src_role, "target": tgt_role,
                        "timestamp": time.time(),
                    }
                    insights.append(insight)
                    self._emergent_insights.append(insight)

        return insights

    # -- Intelligent Cycle --

    def run_intelligent_cycle(
        self, target_url: str,
        beliefs: dict[str, Any] | None = None,
        constraints: list[str] | None = None,
    ) -> dict[str, Any]:
        cycle_result: dict[str, Any] = {
            "cycle": self._cycle_count + 1,
            "target_url": target_url,
        }

        plan = self.build_strategic_plan(f"Full assessment of {target_url}")
        cycle_result["plan"] = plan.to_dict()

        if constraints:
            for c in constraints:
                self.inject_memory_pattern("constraint", c, confidence=0.9)

        tension_results = self.run_all_tensions()
        cycle_result["deliberation"] = [r.to_dict() for r in tension_results]

        pre_opinions = self.collect_opinions(f"Pre-scan assessment of {target_url}")
        cycle_result["pre_opinions"] = {r: o.to_dict() for r, o in pre_opinions.items()}

        scan_result = self.run_cycle(target_url, beliefs)
        cycle_result["scan"] = scan_result

        emergent = self.detect_emergent_behavior()
        cycle_result["emergent_insights"] = emergent

        resolution = self.resolve_disagreements()
        cycle_result["resolution"] = resolution

        cycle_result["usage"] = self.get_aggregate_usage()
        cycle_result["agent_rankings"] = self.get_agent_rankings()
        cycle_result["memory_index_stats"] = self._memory_index.get_stats()

        return cycle_result

    # -- Getters for delegation API --

    def get_emergent_insights(self) -> list[dict[str, Any]]:
        return list(self._emergent_insights)

    def get_deliberation_history(self) -> list[dict[str, Any]]:
        return [r.to_dict() for r in self._deliberation_log]

    def get_memory_injections(self) -> list[dict[str, Any]]:
        return [m.to_dict() for m in self._memory_injections]

    def get_dispatch_history(self) -> list[dict[str, Any]]:
        return [r.to_dict() for r in self._dispatch_history]

    def get_notifications(self) -> list[dict[str, Any]]:
        return [n.to_dict() for n in self._notifications]

    # -- Internal --

    def _on_coordinator_message(self, message: AgentMessage) -> None:
        if message.msg_type == MessageType.TASK_RESULT:
            task_id = message.payload.get("task_id", "")
            if task_id in self._pending_results:
                task = self._pending_results.pop(task_id)
                self._completed_tasks.append(task)
            notification = TaskNotification(**{
                k: message.payload.get(k, v)
                for k, v in TaskNotification().__dict__.items()
                if k in message.payload
            })
            if notification.task_id:
                self._notifications.append(notification)
            for rec in self._dispatch_history:
                if rec.task_id == task_id:
                    rec.status = "completed"
                    rec.completed_at = time.time()
                    break

        elif message.msg_type == MessageType.TASK_FAILED:
            task_id = message.payload.get("task_id", "")
            if task_id in self._pending_results:
                task = self._pending_results.pop(task_id)
                self._completed_tasks.append(task)
            for rec in self._dispatch_history:
                if rec.task_id == task_id:
                    rec.status = message.payload.get("reason", "failed")
                    rec.completed_at = time.time()
                    break

        elif message.msg_type == MessageType.OPINION_SUBMIT:
            logger.debug("Received opinion from %s", message.sender)
        elif message.msg_type == MessageType.OVERRIDE_REQUEST:
            logger.info("Override request from %s: %s", message.sender, message.payload)

    def _on_agent_state_change(
        self, agent_id: str, old: AgentState, new: AgentState,
    ) -> None:
        self._emit_event({
            "type": "agent_state_change",
            "agent_id": agent_id,
            "old_state": old.value, "new_state": new.value,
        })

    def _emit_event(self, event: dict[str, Any]) -> None:
        if self._on_event:
            try:
                self._on_event(event)
            except Exception:
                logger.exception("Event callback failed")

    # -- Serialization --

    def to_dict(self) -> dict[str, Any]:
        return {
            "agents": {r.value: a.to_dict() for r, a in self._agents.items()},
            "shared_context": self._shared_context.to_dict(),
            "mailbox": self._mailbox.to_dict(),
            "cycle_count": self._cycle_count,
            "pending_tasks": len(self._pending_results),
            "completed_tasks": len(self._completed_tasks),
            "agent_weights": self._agent_weights,
            "deliberation_log": [r.to_dict() for r in list(self._deliberation_log)[-10:]],
            "memory_injections": [m.to_dict() for m in self._memory_injections[-10:]],
            "playbook_suggestions": [s.to_dict() for s in self._playbook_suggestions[-5:]],
            "strategic_plans": [p.to_dict() for p in self._strategic_plans[-5:]],
            "current_plan": self._current_plan.to_dict() if self._current_plan else None,
            "emergent_insights": self._emergent_insights[-10:],
            "feedback_loops": {
                k: {kk: vv for kk, vv in v.items() if kk != "transform"}
                for k, v in self._feedback_loops.items()
            },
            "dispatch_history": [r.to_dict() for r in list(self._dispatch_history)[-20:]],
            "notifications": [n.to_dict() for n in list(self._notifications)[-10:]],
            "usage": self.get_aggregate_usage(),
            # E-GAP additions
            "agent_rankings": self.get_agent_rankings(),
            "conflict_resolutions": [r.to_dict() for r in list(self._conflict_resolutions)[-10:]],
            "memory_index": self._memory_index.to_dict(),
            "simulation_results": [r.to_dict() for r in list(self._simulation_results)[-5:]],
            "current_arc": self._current_arc.to_dict() if self._current_arc else None,
            "strategic_arcs": [a.to_dict() for a in self._strategic_arcs[-5:]],
        }
'''

TARGET.write_text(CONTENT, encoding='utf-8')
lines = len(CONTENT.splitlines())
size = TARGET.stat().st_size
print(f"Written {size} bytes, {lines} lines")
