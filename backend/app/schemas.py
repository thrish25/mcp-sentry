"""Pydantic schemas for MCP-Sentry Policy Gateway."""
from enum import Enum
from typing import Any
from pydantic import BaseModel, ConfigDict, Field


class DecisionEnum(str, Enum):
    """Deterministic policy decisions rendered by MCP-Sentry."""

    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"


class ToolCall(BaseModel):
    """Inbound MCP Tool Call invocation request.

    Note: origin and destination fields are treated as untrusted metadata.
    Permissions are strictly determined and verified server-side.
    """

    model_config = ConfigDict(extra="forbid")

    request_id: str = Field(
        ...,
        min_length=1,
        max_length=128,
        description="Unique request correlation ID",
        examples=["req-789a-4bc1"],
    )
    tool_name: str = Field(
        ...,
        min_length=1,
        max_length=128,
        description="Name of the MCP tool requested by the AI agent",
        examples=["read_file", "search_kb"],
    )
    arguments: dict[str, Any] = Field(
        default_factory=dict,
        description="Arguments passed to the MCP tool",
    )
    origin: str = Field(
        ...,
        min_length=1,
        max_length=128,
        description="Untrusted source or agent identifier",
        examples=["agent-analyst-01"],
    )
    destination: str = Field(
        ...,
        min_length=1,
        max_length=128,
        description="Target destination service or server",
        examples=["local-sandbox", "mcp-knowledge-server"],
    )


class PolicyDecision(BaseModel):
    """Structured decision returned by the MCP-Sentry Policy Gateway."""

    decision_id: str = Field(
        ...,
        description="Unique ID for this decision record",
    )
    request_id: str = Field(
        ...,
        description="Correlated request_id from the ToolCall",
    )
    decision: DecisionEnum = Field(
        ...,
        description="ALLOW, BLOCK, or REQUIRE_APPROVAL",
    )
    rule_id: str = Field(
        ...,
        description="Identifier of the specific policy rule that rendered the decision",
    )
    reason: str = Field(
        ...,
        description="Human and machine readable rationale for the decision",
    )
    timestamp: str = Field(
        ...,
        description="ISO 8601 UTC timestamp when decision was rendered",
    )


class ExecutionStatus(str, Enum):
    """Status of mock tool action execution."""

    EXECUTED = "EXECUTED"
    BLOCKED = "BLOCKED"
    PENDING_APPROVAL = "PENDING_APPROVAL"
    APPROVED_EXECUTED = "APPROVED_EXECUTED"
    REJECTED = "REJECTED"


class ExecutionResponse(BaseModel):
    """Result of attempting to execute a tool call through the gateway."""

    request_id: str
    decision: PolicyDecision
    executed: bool
    status: ExecutionStatus
    output: dict[str, Any] | None = None
    error: str | None = None
    message: str | None = None


class ApprovalRequest(BaseModel):
    """Payload to authorize or reject a pending approval request."""

    request_id: str = Field(..., min_length=1)
    approver: str = Field(..., min_length=1, description="Identity of authorized administrator/supervisor")
    approved: bool = Field(..., description="True to authorize execution, False to reject")
    reason: str = Field(default="", description="Optional justification for audit ledger")


class AgentProposeRequest(BaseModel):
    """Request for simulated agent to inspect content and propose a tool call."""

    scenario: str | None = Field(default=None, description="Preset scenario name")
    sample_content: str | None = Field(default=None, description="Custom sample content for agent to analyze")
    requested_tool: str | None = Field(default=None, description="Target tool to propose")


class AgentRunRequest(BaseModel):
    """Request to generate and execute a simulated agent scenario through the gateway."""

    scenario: str = Field(..., min_length=1, description="Name of the scenario to execute")


# ============================================================================
# Phase 4: Audit & Security Findings Schemas
# ============================================================================

class AuditRecordItem(BaseModel):
    """Individual persisted audit ledger entry."""

    request_id: str
    decision_id: str
    tool_name: str
    origin: str
    destination: str
    arguments: dict[str, Any]
    decision: str
    rule_id: str
    reason: str
    status: str
    result: dict[str, Any] | None = None
    created_at: str
    updated_at: str


class PaginatedAuditResponse(BaseModel):
    """Paginated response for audit records."""

    items: list[AuditRecordItem]
    total: int
    page: int
    page_size: int
    total_pages: int


class SecurityFindingItem(BaseModel):
    """Security finding emitted when synthetic canary tokens are accessed or exfiltrated."""

    finding_id: str
    request_id: str
    decision_id: str
    canary_token: str
    canary_name: str
    event_type: str
    severity: str
    evidence: str
    tool_name: str
    origin: str
    destination: str
    created_at: str


class PaginatedFindingsResponse(BaseModel):
    """Paginated response for security investigation findings."""

    items: list[SecurityFindingItem]
    total: int
    page: int
    page_size: int
    total_pages: int


class RecentDecisionItem(BaseModel):
    """Correlated recent decision entry linking request_id and decision_id."""

    request_id: str
    decision_id: str
    tool_name: str
    origin: str
    destination: str
    decision: str
    rule_id: str
    reason: str
    status: str
    created_at: str


class AggregateMetricsResponse(BaseModel):
    """High-level metrics and aggregate counts for security overview."""

    total_events: int
    allow_count: int
    block_count: int
    require_approval_count: int
    executed_count: int
    blocked_count: int
    pending_approval_count: int
    total_findings: int
    findings_by_severity: dict[str, int]
    active_canaries_count: int
    fake_outbox_count: int
    fake_network_logs_count: int


class CanaryTokenItem(BaseModel):
    """Synthetic canary token registered in the environment."""

    token_value: str
    name: str
    file_path: str
    severity: str
    description: str
    created_at: str


class ApprovalEventItem(BaseModel):
    """Ledger record of a human approval or rejection action."""

    id: int
    request_id: str
    decision_id: str
    approver: str
    approved: bool
    reason: str
    status_before: str = ""
    status_after: str = ""
    created_at: str


# ============================================================================
# Phase 7: Evaluation & Demo Schemas
# ============================================================================

class DemoStepResultItem(BaseModel):
    """Outcome of an individual demonstration scenario step."""

    step_number: int
    scenario_id: str
    name: str
    description: str
    tool_name: str
    expected_decision: str
    actual_decision: str
    match: bool
    status: str
    rule_id: str
    reason: str
    request_id: str
    canary_findings_count: int
    findings: list[dict[str, Any]] = Field(default_factory=list)
    output: dict[str, Any] | None = None
    error: str | None = None


class SequentialDemoResponse(BaseModel):
    """Complete response containing all executed demo steps."""

    timestamp: str
    total_steps: int
    all_matched: bool
    steps: list[DemoStepResultItem]


class EvaluationMetrics(BaseModel):
    """Calculated empirical security metrics with zero-division safeguards."""

    unauthorized_call_block_rate_percent: float
    legitimate_action_false_block_rate_percent: float
    canary_detection_precision_percent: float
    canary_detection_recall_percent: float
    audit_record_completeness_percent: float


class EvaluationDenominators(BaseModel):
    """Raw counts and denominators defining evaluation metrics."""

    unauthorized_total: int
    unauthorized_blocked: int
    legitimate_total: int
    legitimate_blocked: int
    legitimate_allowed: int
    legitimate_approved: int
    canary_present_total: int
    canary_true_positives: int
    canary_false_positives: int
    canary_false_negatives: int
    canary_true_negatives: int
    total_audited_calls: int


class EvaluationReportResponse(BaseModel):
    """Comprehensive evaluation report from labeled dataset execution."""

    evaluation_timestamp: str
    execution_duration_seconds: float
    total_test_cases: int
    metrics: EvaluationMetrics
    denominators: EvaluationDenominators
    summary: str
    test_details: list[dict[str, Any]]



