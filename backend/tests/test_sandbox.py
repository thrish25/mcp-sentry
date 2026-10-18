"""Comprehensive test suite for Phase 3: Isolated Mock Tool Sandbox, Execution Service, and Simulated Agent."""
import pytest
from fastapi.testclient import TestClient

from app.agent import SimulatedAgent, simulated_agent
from app.database import Database, db
from app.execution import ExecutionService, execution_service
from app.main import app
from app.sandbox import MockSandbox
from app.schemas import DecisionEnum, ExecutionStatus, ToolCall

client = TestClient(app)


# ============================================================================
# 1. SYNTHETIC FILES & RESTRICTED FILESYSTEM ACCESS
# ============================================================================

def test_read_synthetic_file_operates_strictly_on_mock_data() -> None:
    """Reading an authorized path returns harmless synthetic data from the mock dataset."""
    tool_call = ToolCall(
        request_id="test-synth-001",
        tool_name="read_file",
        arguments={"path": "/workspace/data/system_info.json"},
        origin="agent-analyst",
        destination="local-sandbox",
    )
    result = execution_service.execute_tool_call(tool_call)
    assert result.executed is True
    assert result.status == ExecutionStatus.EXECUTED
    assert result.output is not None
    assert "IBM Z Mainframe Virtual Partition" in result.output["content"]
    assert result.output["source"] == "synthetic_file_store"


def test_synthetic_files_seeded_properly() -> None:
    """Verify predefined harmless synthetic files exist in the mock repository."""
    files = db.list_synthetic_files()
    paths = [f["path"] for f in files]
    assert "/workspace/data/system_info.json" in paths
    assert "/workspace/data/security_report.txt" in paths
    assert "/workspace/data/user_directory.csv" in paths
    assert "/workspace/scratch/sample.txt" in paths


def test_write_to_synthetic_scratch_updates_mock_store() -> None:
    """Writing to scratch saves to the synthetic dataset without touching the host disk."""
    scratch_path = "/workspace/scratch/test_calc.txt"
    test_content = "Synthetic result: checksum=0x4A1F"
    tool_call = ToolCall(
        request_id="test-synth-write-001",
        tool_name="write_file",
        arguments={"path": scratch_path, "content": test_content},
        origin="agent-analyst",
        destination="local-sandbox",
    )
    result = execution_service.execute_tool_call(tool_call)
    assert result.executed is True
    assert result.status == ExecutionStatus.EXECUTED

    # Verify content in synthetic store
    stored = db.get_synthetic_file(scratch_path)
    assert stored == test_content


def test_nonexistent_synthetic_file_handled_safely() -> None:
    """Non-existent file within permitted root returns safe error without exposing host disk."""
    tool_call = ToolCall(
        request_id="test-synth-missing-001",
        tool_name="read_file",
        arguments={"path": "/workspace/data/missing_doc.json"},
        origin="agent-analyst",
        destination="local-sandbox",
    )
    result = execution_service.execute_tool_call(tool_call)
    assert result.executed is False or "error" in (result.output or {})
    assert "Synthetic file" in str(result.output)


# ============================================================================
# 2. BLOCKED CALLS NEVER EXECUTE MOCK ACTIONS
# ============================================================================

def test_path_traversal_never_executes_action() -> None:
    """Path traversal attempt must be blocked by the policy engine and never execute in sandbox."""
    tool_call = ToolCall(
        request_id="test-block-traversal-001",
        tool_name="read_file",
        arguments={"path": "../../etc/shadow"},
        origin="agent-attacker",
        destination="local-sandbox",
    )
    result = execution_service.execute_tool_call(tool_call)
    assert result.executed is False
    assert result.status == ExecutionStatus.BLOCKED
    assert result.decision.decision == DecisionEnum.BLOCK
    assert result.output is None

    # Verify audit record persists the blocked status
    record = db.get_audit_record("test-block-traversal-001")
    assert record is not None
    assert record["status"] == "BLOCKED"
    assert record["decision"] == "BLOCK"


def test_unknown_tool_never_executes_action() -> None:
    """Ungranted tool must be rejected by default-deny and never executed."""
    tool_call = ToolCall(
        request_id="test-block-unknown-001",
        tool_name="spawn_reverse_shell",
        arguments={"ip": "10.0.0.1"},
        origin="agent-attacker",
        destination="local-sandbox",
    )
    result = execution_service.execute_tool_call(tool_call)
    assert result.executed is False
    assert result.status == ExecutionStatus.BLOCKED
    assert result.decision.rule_id == "RULE-DEFAULT-DENY"
    assert result.output is None


def test_dangerous_command_never_executes() -> None:
    """Dangerous shell commands are blocked and never executed."""
    tool_call = ToolCall(
        request_id="test-block-cmd-001",
        tool_name="execute_command",
        arguments={"command": "rm -rf /"},
        origin="agent-attacker",
        destination="isolated-runner",
    )
    result = execution_service.execute_tool_call(tool_call)
    assert result.executed is False
    assert result.status == ExecutionStatus.BLOCKED
    assert result.decision.rule_id == "RULE-DANGEROUS-COMMAND"
    assert result.output is None


# ============================================================================
# 3. FAKE EMAIL OUTBOX & APPROVAL WORKFLOW
# ============================================================================

def test_send_email_remains_pending_without_premature_execution() -> None:
    """Email dispatch must require approval and NOT populate outbox before authorization."""
    req_id = "test-email-pending-001"
    initial_email_count = len(db.list_emails())

    tool_call = ToolCall(
        request_id=req_id,
        tool_name="send_email",
        arguments={
            "to": "compliance@internal.ibm.z",
            "subject": "Confidential Security Audit Log",
            "body": "System integrity verified on z/OS partition.",
        },
        origin="agent-sec",
        destination="mail-gateway",
    )
    result = execution_service.execute_tool_call(tool_call)
    assert result.executed is False
    assert result.status == ExecutionStatus.PENDING_APPROVAL
    assert result.decision.decision == DecisionEnum.REQUIRE_APPROVAL

    # PROVE: Outbox count has NOT changed while pending
    assert len(db.list_emails()) == initial_email_count


def test_send_email_approval_executes_to_fake_outbox() -> None:
    """When approved via backend workflow, email is recorded strictly into local SQLite outbox."""
    import uuid
    req_id = f"test-email-approved-{uuid.uuid4().hex[:8]}"
    tool_call = ToolCall(
        request_id=req_id,
        tool_name="send_email",
        arguments={
            "to": "officer@internal.ibm.z",
            "subject": "Approved Security Notification",
            "body": "Notification body text.",
        },
        origin="agent-sec",
        destination="mail-gateway",
    )
    initial_res = execution_service.execute_tool_call(tool_call)
    assert initial_res.status == ExecutionStatus.PENDING_APPROVAL

    # Execute backend approval
    approval_res = execution_service.resolve_approval(
        request_id=req_id,
        approver="supervisor-alice",
        approved=True,
        reason="Verified quarterly communication.",
    )
    assert approval_res.executed is True
    assert approval_res.status == ExecutionStatus.APPROVED_EXECUTED
    assert approval_res.output is not None
    assert approval_res.output["approved_by"] == "supervisor-alice"

    # PROVE: Record is in fake_email_outbox table
    emails = db.list_emails()
    matched = [e for e in emails if e["request_id"] == req_id]
    assert len(matched) == 1
    assert matched[0]["to_address"] == "officer@internal.ibm.z"
    assert matched[0]["subject"] == "Approved Security Notification"


def test_rejection_workflow_prevents_email_dispatch() -> None:
    """Rejecting an action sets status to REJECTED and leaves outbox empty for that request."""
    import uuid
    req_id = f"test-email-rejected-{uuid.uuid4().hex[:8]}"
    tool_call = ToolCall(
        request_id=req_id,
        tool_name="send_email",
        arguments={
            "to": "external@unknown.com",
            "subject": "Suspicious Exfil",
            "body": "Dump data",
        },
        origin="agent-sec",
        destination="mail-gateway",
    )
    execution_service.execute_tool_call(tool_call)

    # Reject
    rejection_res = execution_service.resolve_approval(
        request_id=req_id,
        approver="security-officer-bob",
        approved=False,
        reason="Disallowed destination address.",
    )
    assert rejection_res.executed is False
    assert rejection_res.status == ExecutionStatus.REJECTED

    # PROVE: No email was queued or sent
    emails = [e for e in db.list_emails() if e["request_id"] == req_id]
    assert len(emails) == 0


# ============================================================================
# 4. FAKE NETWORK LOGS & NO EXTERNAL TRAFFIC
# ============================================================================

def test_fetch_internal_url_records_to_fake_network_logs() -> None:
    """Authorized internal simulated URL call logs simulated transaction locally."""
    import uuid
    req_id = f"test-net-{uuid.uuid4().hex[:8]}"
    tool_call = ToolCall(
        request_id=req_id,
        tool_name="fetch_url",
        arguments={"url": "http://internal/health"},
        origin="agent-mon",
        destination="internal-api-gateway",
    )
    result = execution_service.execute_tool_call(tool_call)
    assert result.executed is True
    assert result.status == ExecutionStatus.EXECUTED
    assert result.output["simulated"] is True

    # PROVE: Logged in fake_network_logs table
    logs = db.list_network_logs()
    matched = [log for log in logs if log["request_id"] == req_id]
    assert len(matched) == 1
    assert matched[0]["url"] == "http://internal/health"
    assert matched[0]["status_code"] == 200


def test_fetch_external_url_blocked_and_never_logged() -> None:
    """Accessing external internet URLs is rejected by policy and never contacts external network."""
    req_id = "test-net-blocked-001"
    tool_call = ToolCall(
        request_id=req_id,
        tool_name="fetch_url",
        arguments={"url": "http://malicious-external-target.com/api/steal"},
        origin="agent-mon",
        destination="internal-api-gateway",
    )
    result = execution_service.execute_tool_call(tool_call)
    assert result.executed is False
    assert result.status == ExecutionStatus.BLOCKED
    assert result.decision.rule_id == "RULE-UNAUTHORIZED-URL"

    # PROVE: No network log created for blocked request
    logs = [log for log in db.list_network_logs() if log["request_id"] == req_id]
    assert len(logs) == 0


# ============================================================================
# 5. SIMULATED AGENT
# ============================================================================

def test_simulated_agent_proposes_legitimate_scenario() -> None:
    """SimulatedAgent proposes a valid ToolCall for legitimate scenarios."""
    call = simulated_agent.propose_tool_call(scenario="read_system_info")
    assert call.tool_name == "read_file"
    assert call.arguments["path"] == "/workspace/data/system_info.json"
    assert call.destination == "local-sandbox"


def test_simulated_agent_proposes_from_sample_content() -> None:
    """SimulatedAgent inspects content and formats structured ToolCall."""
    content = "System CPU metrics are nominal: metrics requested."
    call = simulated_agent.propose_tool_call(sample_content=content)
    assert call.tool_name == "query_metrics"
    assert "metric_name" in call.arguments


def test_simulated_agent_runs_scenario_through_gateway() -> None:
    """SimulatedAgent.run_scenario goes through full policy gateway arbitration."""
    # Benign scenario
    res_allowed = simulated_agent.run_scenario(scenario="read_security_report")
    assert res_allowed.executed is True
    assert res_allowed.status == ExecutionStatus.EXECUTED

    # Malicious scenario
    res_blocked = simulated_agent.run_scenario(scenario="attack_path_traversal")
    assert res_blocked.executed is False
    assert res_blocked.status == ExecutionStatus.BLOCKED


# ============================================================================
# 6. FASTAPI SANDBOX & AGENT ENDPOINTS
# ============================================================================

def test_api_sandbox_execute_allow() -> None:
    """POST /api/v1/sandbox/execute executes allowed tool call and returns result."""
    payload = {
        "request_id": "test-api-exec-001",
        "tool_name": "query_metrics",
        "arguments": {"metric_name": "arbitration_time_ms"},
        "origin": "agent-01",
        "destination": "metrics-service",
    }
    response = client.post("/api/v1/sandbox/execute", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["executed"] is True
    assert data["status"] == "EXECUTED"
    assert data["output"]["metric_name"] == "arbitration_time_ms"


def test_api_sandbox_execute_block_does_not_execute() -> None:
    """POST /api/v1/sandbox/execute returns blocked status without execution."""
    payload = {
        "request_id": "test-api-block-001",
        "tool_name": "read_file",
        "arguments": {"path": "../../etc/shadow"},
        "origin": "agent-01",
        "destination": "local-sandbox",
    }
    response = client.post("/api/v1/sandbox/execute", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["executed"] is False
    assert data["status"] == "BLOCKED"
    assert data["decision"]["decision"] == "BLOCK"


def test_api_sandbox_approval_cycle() -> None:
    """POST /api/v1/sandbox/approve workflow via HTTP endpoint."""
    import uuid
    req_id = f"test-api-approval-{uuid.uuid4().hex[:8]}"
    # 1. Trigger an approval-required tool
    payload = {
        "request_id": req_id,
        "tool_name": "database_migration",
        "arguments": {"migration_id": "mig_api_001"},
        "origin": "agent-admin",
        "destination": "db-server",
    }
    exec_resp = client.post("/api/v1/sandbox/execute", json=payload)
    assert exec_resp.status_code == 200
    assert exec_resp.json()["status"] == "PENDING_APPROVAL"

    # 2. Approve it via API
    approval_payload = {
        "request_id": req_id,
        "approver": "lead-dba-charlie",
        "approved": True,
        "reason": "Authorized migration.",
    }
    approve_resp = client.post("/api/v1/sandbox/approve", json=approval_payload)
    assert approve_resp.status_code == 200
    data = approve_resp.json()
    assert data["executed"] is True
    assert data["status"] == "APPROVED_EXECUTED"
    assert data["output"]["approved_by"] == "lead-dba-charlie"


def test_api_inspect_outbox_and_logs() -> None:
    """GET /api/v1/sandbox/outbox and network-logs return valid lists."""
    r_outbox = client.get("/api/v1/sandbox/outbox")
    assert r_outbox.status_code == 200
    assert "emails" in r_outbox.json()

    r_logs = client.get("/api/v1/sandbox/network-logs")
    assert r_logs.status_code == 200
    assert "network_logs" in r_logs.json()

    r_files = client.get("/api/v1/sandbox/files")
    assert r_files.status_code == 200
    assert "files" in r_files.json()

    r_audit = client.get("/api/v1/sandbox/audit-records")
    assert r_audit.status_code == 200
    assert "audit_records" in r_audit.json()


def test_api_agent_propose_and_run() -> None:
    """POST /api/v1/agent/propose and /api/v1/agent/run endpoints work end-to-end."""
    prop_resp = client.post("/api/v1/agent/propose", json={"scenario": "system_info"})
    assert prop_resp.status_code == 200
    assert prop_resp.json()["tool_name"] == "read_file"

    run_resp = client.post("/api/v1/agent/run", json={"scenario": "system_info"})
    assert run_resp.status_code == 200
    assert run_resp.json()["status"] == "EXECUTED"
