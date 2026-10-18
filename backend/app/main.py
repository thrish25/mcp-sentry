"""FastAPI entrypoint for MCP-Sentry: Runtime Security Gateway for AI Agents."""
from datetime import datetime, timezone
from typing import Any
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware

from app.agent import simulated_agent
from app.config import get_settings
from app.database import db
from app.evaluation import evaluation_engine
from app.execution import execution_service
from app.policy import PolicyEngine, PERMISSION_CATALOG
from app.schemas import (
    AgentProposeRequest,
    AgentRunRequest,
    AggregateMetricsResponse,
    ApprovalEventItem,
    ApprovalRequest,
    AuditRecordItem,
    CanaryTokenItem,
    DecisionEnum,
    DemoStepResultItem,
    EvaluationReportResponse,
    ExecutionResponse,
    PaginatedAuditResponse,
    PaginatedFindingsResponse,
    PolicyDecision,
    RecentDecisionItem,
    SecurityFindingItem,
    SequentialDemoResponse,
    ToolCall,
)

settings = get_settings()

app = FastAPI(
    title=settings.app_name,
    version=settings.version,
    description="Runtime Security Gateway for AI Agents — IBM Z Datathon Project",
)

# CORS configuration for frontend integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/", tags=["General"])
def read_root() -> dict[str, str]:
    """Root landing endpoint with gateway status."""
    return {
        "status": "online",
        "message": "MCP-Sentry Gateway is active",
        "version": settings.version,
        "docs_url": "/docs",
    }


@app.get("/health", tags=["Health"])
def health_check() -> dict[str, str]:
    """Gateway health check endpoint."""
    return {
        "status": "healthy",
        "service": "mcp-sentry-backend",
        "version": settings.version,
        "environment": settings.environment,
    }


# ============================================================================
# Policy Engine Endpoints
# ============================================================================

@app.post(
    "/api/v1/policy/evaluate",
    response_model=PolicyDecision,
    tags=["Policy Gateway"],
    summary="Evaluate an inbound MCP tool call against security policies",
)
def evaluate_tool_call(tool_call: ToolCall) -> PolicyDecision:
    """Deterministically arbitrate an inbound AI agent MCP tool invocation.

    Returns a structured decision: ALLOW, BLOCK, or REQUIRE_APPROVAL.
    Authorization is performed entirely backend-side with default-deny semantics.
    Persists decision to audit ledger even when no execution follows.
    """
    decision = PolicyEngine.evaluate(tool_call)

    # Persist policy decision even when no execution follows (Requirements 1, 3)
    status = "EVALUATED" if decision.decision == DecisionEnum.ALLOW else decision.decision.value
    db.insert_audit_record(
        request_id=tool_call.request_id,
        decision_id=decision.decision_id,
        tool_name=tool_call.tool_name,
        origin=tool_call.origin,
        destination=tool_call.destination,
        arguments=tool_call.arguments,
        decision=decision.decision.value,
        rule_id=decision.rule_id,
        reason=decision.reason,
        status=status,
        result={"evaluated_only": True},
    )
    return decision



@app.get(
    "/api/v1/policy/permissions",
    tags=["Policy Gateway"],
    summary="List all registered tool security policies",
)
def list_permissions() -> dict[str, list[dict[str, object]]]:
    """Return the active permission catalog specifications."""
    policies = [
        {
            "tool_name": policy.name,
            "allowed_destinations": policy.allowed_destinations,
            "required_arguments": policy.required_arguments,
            "requires_approval": policy.requires_approval,
            "allow_rule_id": policy.allow_rule_id,
            "approval_rule_id": policy.approval_rule_id,
        }
        for policy in PERMISSION_CATALOG.values()
    ]
    return {"tools": policies}


# ============================================================================
# Sandbox Execution & Approval Endpoints
# ============================================================================

@app.post(
    "/api/v1/sandbox/execute",
    response_model=ExecutionResponse,
    tags=["Tool Sandbox"],
    summary="Execute a tool call through policy arbitration into the mock sandbox",
)
def execute_tool(tool_call: ToolCall) -> ExecutionResponse:
    """Execute a tool call behind the policy gateway.

    Guarantees:
    - PolicyEngine is always evaluated first.
    - BLOCK never executes.
    - REQUIRE_APPROVAL remains pending.
    - ALLOW operates strictly on synthetic mock data.
    """
    return execution_service.execute_tool_call(tool_call)


@app.post(
    "/api/v1/sandbox/approve",
    response_model=ExecutionResponse,
    tags=["Tool Sandbox"],
    summary="Approve or reject a pending tool execution",
)
def resolve_approval(approval_req: ApprovalRequest) -> ExecutionResponse:
    """Explicit backend approval workflow to authorize or reject pending actions."""
    try:
        return execution_service.resolve_approval(
            request_id=approval_req.request_id,
            approver=approval_req.approver,
            approved=approval_req.approved,
            reason=approval_req.reason,
        )
    except ValueError as err:
        raise HTTPException(status_code=400, detail=str(err)) from err


@app.get(
    "/api/v1/sandbox/outbox",
    tags=["Tool Sandbox"],
    summary="View fake email outbox records",
)
def list_outbox() -> dict[str, list[dict[str, Any]]]:
    """Return simulated outgoing emails stored locally in SQLite."""
    return {"emails": db.list_emails()}


@app.get(
    "/api/v1/sandbox/network-logs",
    tags=["Tool Sandbox"],
    summary="View fake network logs",
)
def list_network_logs() -> dict[str, list[dict[str, Any]]]:
    """Return simulated network request logs stored locally without external traffic."""
    return {"network_logs": db.list_network_logs()}


@app.get(
    "/api/v1/sandbox/files",
    tags=["Tool Sandbox"],
    summary="List synthetic sandbox files",
)
def list_synthetic_files() -> dict[str, list[dict[str, Any]]]:
    """List harmless sample files available in the synthetic sandbox."""
    return {"files": db.list_synthetic_files()}


@app.get(
    "/api/v1/sandbox/audit-records",
    tags=["Tool Sandbox"],
    summary="List audit records of tool calls",
)
def list_audit_records() -> dict[str, list[dict[str, Any]]]:
    """Return audit ledger entries tracking policy decisions and execution status."""
    return {"audit_records": db.list_audit_records()}


# ============================================================================
# Simulated Agent Endpoints
# ============================================================================

@app.post(
    "/api/v1/agent/propose",
    response_model=ToolCall,
    tags=["Simulated Agent"],
    summary="Simulated agent analyzes content and proposes structured ToolCall",
)
def agent_propose(req: AgentProposeRequest) -> ToolCall:
    """Have the simulated agent construct a ToolCall from sample content or scenario."""
    try:
        return simulated_agent.propose_tool_call(
            scenario=req.scenario,
            sample_content=req.sample_content,
            requested_tool=req.requested_tool,
        )
    except ValueError as err:
        raise HTTPException(status_code=400, detail=str(err)) from err


@app.post(
    "/api/v1/agent/run",
    response_model=ExecutionResponse,
    tags=["Simulated Agent"],
    summary="Run a simulated agent scenario through the policy gateway",
)
def agent_run(req: AgentRunRequest) -> ExecutionResponse:
    """Propose and arbitrate a simulated agent scenario."""
    try:
        return simulated_agent.run_scenario(scenario=req.scenario)
    except ValueError as err:
        raise HTTPException(status_code=400, detail=str(err)) from err


# ============================================================================
# Phase 4: Audit Ledger, Canary Detection & Forensic Endpoints
# ============================================================================

@app.get(
    "/api/v1/audit/events",
    response_model=PaginatedAuditResponse,
    tags=["Audit & Forensics"],
    summary="Get paginated audit events with optional filtering",
)
def get_audit_events(
    page: int = Query(default=1, ge=1, description="Page number (1-indexed)"),
    page_size: int = Query(default=20, ge=1, le=100, description="Items per page"),
    decision: str | None = Query(default=None, description="Filter by decision: ALLOW, BLOCK, REQUIRE_APPROVAL"),
    status: str | None = Query(default=None, description="Filter by status: EXECUTED, BLOCKED, etc."),
    tool_name: str | None = Query(default=None, description="Filter by tool name"),
) -> PaginatedAuditResponse:
    """Query paginated audit ledger events tracking tool calls, decisions, and execution outcomes."""
    data = db.list_audit_records_paginated(
        page=page,
        page_size=page_size,
        decision=decision,
        status=status,
        tool_name=tool_name,
    )
    return PaginatedAuditResponse(**data)


@app.get(
    "/api/v1/audit/findings",
    response_model=PaginatedFindingsResponse,
    tags=["Audit & Forensics"],
    summary="Get paginated security findings from synthetic canary tokens",
)
def get_security_findings(
    page: int = Query(default=1, ge=1, description="Page number (1-indexed)"),
    page_size: int = Query(default=20, ge=1, le=100, description="Items per page"),
    severity: str | None = Query(default=None, description="Filter by severity: CRITICAL, HIGH, MEDIUM"),
    event_type: str | None = Query(default=None, description="Filter by event type"),
) -> PaginatedFindingsResponse:
    """Query paginated security findings triggered by canary access or attempted exfiltration."""
    data = db.list_security_findings(
        page=page,
        page_size=page_size,
        severity=severity,
        event_type=event_type,
    )
    return PaginatedFindingsResponse(**data)


@app.get(
    "/api/v1/audit/recent-decisions",
    response_model=list[RecentDecisionItem],
    tags=["Audit & Forensics"],
    summary="Get recent policy decisions linked by request_id and decision_id",
)
def get_recent_decisions(
    limit: int = Query(default=10, ge=1, le=100, description="Number of recent decisions"),
) -> list[RecentDecisionItem]:
    """Retrieve recent policy decisions linking request_id, decision_id, rule_id, and rationale."""
    raw_items = db.get_recent_decisions(limit=limit)
    return [RecentDecisionItem(**item) for item in raw_items]


@app.get(
    "/api/v1/audit/metrics",
    response_model=AggregateMetricsResponse,
    tags=["Audit & Forensics"],
    summary="Get aggregate counts and security metrics",
)
def get_aggregate_metrics() -> AggregateMetricsResponse:
    """Retrieve operational and security aggregate counts."""
    counts = db.get_aggregate_counts()
    return AggregateMetricsResponse(**counts)


@app.get(
    "/api/v1/audit/canaries",
    response_model=list[CanaryTokenItem],
    tags=["Audit & Forensics"],
    summary="List registered synthetic canary tokens",
)
def list_canary_tokens() -> list[CanaryTokenItem]:
    """Return all active synthetic canary tokens configured in the gateway."""
    tokens = db.list_canary_tokens()
    return [CanaryTokenItem(**t) for t in tokens]


@app.get(
    "/api/v1/audit/approvals",
    response_model=list[ApprovalEventItem],
    tags=["Audit & Forensics"],
    summary="List approval and rejection audit events",
)
def list_approval_events(
    request_id: str | None = Query(default=None, description="Filter by request_id"),
) -> list[ApprovalEventItem]:
    """Return audit records of human approval or rejection actions."""
    events = db.list_approval_events(request_id=request_id)
    return [
        ApprovalEventItem(
            id=e["id"],
            request_id=e["request_id"],
            decision_id=e["decision_id"],
            approver=e["approver"],
            approved=bool(e["approved"]),
            reason=e["reason"] or "",
            status_before=e.get("status_before") or "",
            status_after=e.get("status_after") or "",
            created_at=e["created_at"],
        )
        for e in events
    ]


# ============================================================================
# Phase 7: Reproducible Demo & Evaluation Endpoints
# ============================================================================

@app.post(
    "/api/v1/evaluation/demo",
    response_model=SequentialDemoResponse,
    tags=["Evaluation & Demo"],
    summary="Execute the 7 predefined demonstration scenarios in sequence",
)
def run_sequential_demo() -> SequentialDemoResponse:
    """Run all 7 required scenarios and return expected vs actual decisions."""
    step_results = evaluation_engine.run_sequential_demo()
    steps_data = [
        DemoStepResultItem(
            step_number=r.step_number,
            scenario_id=r.scenario_id,
            name=r.name,
            description=r.description,
            tool_name=r.tool_name,
            expected_decision=r.expected_decision,
            actual_decision=r.actual_decision,
            match=r.match,
            status=r.status,
            rule_id=r.rule_id,
            reason=r.reason,
            request_id=r.request_id,
            canary_findings_count=r.canary_findings_count,
            findings=r.findings,
            output=r.output,
            error=r.error,
        )
        for r in step_results
    ]
    all_matched = all(s.match for s in steps_data)
    now_iso = datetime.now(timezone.utc).isoformat()
    return SequentialDemoResponse(
        timestamp=now_iso,
        total_steps=len(steps_data),
        all_matched=all_matched,
        steps=steps_data,
    )


@app.post(
    "/api/v1/evaluation/run",
    response_model=EvaluationReportResponse,
    tags=["Evaluation & Demo"],
    summary="Execute empirical security evaluation over labeled test dataset",
)
def run_evaluation_suite() -> EvaluationReportResponse:
    """Execute labeled dataset, calculate block rate, false-block rate, precision, recall, and audit completeness."""
    data = evaluation_engine.run_evaluation()
    return EvaluationReportResponse(**data)


