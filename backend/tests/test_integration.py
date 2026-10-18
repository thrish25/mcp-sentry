"""Phase 6 Integration Tests for MCP-Sentry.

Verifies:
- CORS behavior for allowed vs disallowed origins.
- Policy recheck in the approval workflow preventing blocked actions from executing.
- End-to-end scenario execution (ALLOW, BLOCK, REQUIRE_APPROVAL).
- Validation error responses.
- Decoupled canary detection and sandbox isolation.
"""
import uuid
import pytest
from fastapi.testclient import TestClient

from app.database import db
from app.execution import execution_service
from app.main import app
from app.schemas import ExecutionStatus, ToolCall


@pytest.fixture
def client() -> TestClient:
    """FastAPI TestClient fixture."""
    return TestClient(app)


def test_cors_allowed_origins(client: TestClient) -> None:
    """CORS allows local frontend origins http://localhost:3000 and http://127.0.0.1:3000."""
    res_localhost = client.options(
        "/api/v1/audit/metrics",
        headers={
            "Origin": "http://localhost:3000",
            "Access-Control-Request-Method": "GET",
        },
    )
    assert res_localhost.status_code == 200
    assert res_localhost.headers.get("access-control-allow-origin") == "http://localhost:3000"

    res_127 = client.options(
        "/api/v1/audit/metrics",
        headers={
            "Origin": "http://127.0.0.1:3000",
            "Access-Control-Request-Method": "GET",
        },
    )
    assert res_127.status_code == 200
    assert res_127.headers.get("access-control-allow-origin") == "http://127.0.0.1:3000"


def test_cors_disallowed_origin(client: TestClient) -> None:
    """CORS does not allow unauthorized external origins."""
    res_external = client.options(
        "/api/v1/audit/metrics",
        headers={
            "Origin": "http://evil-external-site.com",
            "Access-Control-Request-Method": "GET",
        },
    )
    # FastAPIs CORSMiddleware does not return access-control-allow-origin for unauthorized origins
    assert res_external.headers.get("access-control-allow-origin") is None


def test_approval_policy_recheck_blocks_malicious_action(client: TestClient) -> None:
    """Policy recheck in resolve_approval prevents blocked actions from executing even if approved=True."""
    req_id = f"test-tampered-{uuid.uuid4().hex[:8]}"

    # Simulate an audit record that was somehow left pending approval for a dangerous command
    db.insert_audit_record(
        request_id=req_id,
        decision_id=f"dec-{uuid.uuid4().hex[:8]}",
        tool_name="execute_command",
        origin="simulated-agent-ibmz",
        destination="isolated-runner",
        arguments={"command": "rm -rf /"},
        decision="REQUIRE_APPROVAL",
        rule_id="TEST-RULE",
        reason="Test tampered record",
        status=ExecutionStatus.PENDING_APPROVAL.value,
        result=None,
    )

    # Attempt to approve the dangerous action via the API
    res = client.post(
        "/api/v1/sandbox/approve",
        json={
            "request_id": req_id,
            "approver": "supervisor-alice",
            "approved": True,
            "reason": "Accidentally approved malicious command",
        },
    )
    # The policy recheck must fail and reject with HTTP 400
    assert res.status_code == 400
    assert "Policy recheck violation" in res.json()["detail"]

    # Verify audit record status was updated to BLOCKED, NOT APPROVED_EXECUTED
    record = db.get_audit_record(req_id)
    assert record is not None
    assert record["status"] == ExecutionStatus.BLOCKED.value


def test_approval_workflow_success_and_recheck(client: TestClient) -> None:
    """A legitimate approval-required tool call rechecks policy and executes on approval."""
    req_id = f"test-legit-approval-{uuid.uuid4().hex[:8]}"
    tool_call = ToolCall(
        request_id=req_id,
        tool_name="send_email",
        arguments={
            "to": "officer@internal.ibm.z",
            "subject": "Verified System Notice",
            "body": "System health verified nominal.",
        },
        origin="agent-sec",
        destination="mail-gateway",
    )
    initial_res = execution_service.execute_tool_call(tool_call)
    assert initial_res.status == ExecutionStatus.PENDING_APPROVAL

    # Approve via backend endpoint
    res = client.post(
        "/api/v1/sandbox/approve",
        json={
            "request_id": req_id,
            "approver": "security-officer-bob",
            "approved": True,
            "reason": "Authorized legitimate security notice",
        },
    )
    assert res.status_code == 200
    data = res.json()
    assert data["executed"] is True
    assert data["status"] == "APPROVED_EXECUTED"
    assert data["output"]["approved_by"] == "security-officer-bob"


def test_scenario_execution_allow(client: TestClient) -> None:
    """Submitting a safe scenario executes and returns ALLOW."""
    res = client.post("/api/v1/agent/run", json={"scenario": "read_system_info"})
    assert res.status_code == 200
    data = res.json()
    assert data["decision"]["decision"] == "ALLOW"
    assert data["executed"] is True
    assert data["status"] == "EXECUTED"


def test_scenario_execution_require_approval(client: TestClient) -> None:
    """Submitting an approval-required scenario returns REQUIRE_APPROVAL and leaves status pending."""
    res = client.post("/api/v1/agent/run", json={"scenario": "send_alert_email"})
    assert res.status_code == 200
    data = res.json()
    assert data["decision"]["decision"] == "REQUIRE_APPROVAL"
    assert data["executed"] is False
    assert data["status"] == "PENDING_APPROVAL"


def test_scenario_execution_block(client: TestClient) -> None:
    """Submitting an attack scenario returns BLOCK and never executes."""
    res = client.post("/api/v1/agent/run", json={"scenario": "attack_path_traversal"})
    assert res.status_code == 200
    data = res.json()
    assert data["decision"]["decision"] == "BLOCK"
    assert data["executed"] is False
    assert data["status"] == "BLOCKED"


def test_validation_error_format(client: TestClient) -> None:
    """Sending invalid payload returns 422 with structured validation details."""
    res = client.post("/api/v1/sandbox/execute", json={})
    assert res.status_code == 422
    data = res.json()
    assert "detail" in data
    assert isinstance(data["detail"], list)


def test_all_dashboard_endpoints_accessible(client: TestClient) -> None:
    """Verify all endpoints queried by the frontend dashboard are active and return matching schemas."""
    # 1. Health
    h = client.get("/health")
    assert h.status_code == 200
    assert h.json()["status"] == "healthy"

    # 2. Metrics
    m = client.get("/api/v1/audit/metrics")
    assert m.status_code == 200
    assert "total_events" in m.json()
    assert "allow_count" in m.json()

    # 3. Events
    e = client.get("/api/v1/audit/events?page=1&page_size=5")
    assert e.status_code == 200
    assert "items" in e.json()
    assert "total" in e.json()

    # 4. Findings
    f = client.get("/api/v1/audit/findings?page=1&page_size=5")
    assert f.status_code == 200
    assert "items" in f.json()

    # 5. Canaries
    c = client.get("/api/v1/audit/canaries")
    assert c.status_code == 200
    assert isinstance(c.json(), list)

    # 6. Approvals
    a = client.get("/api/v1/audit/approvals")
    assert a.status_code == 200
    assert isinstance(a.json(), list)

    # 7. Sandbox Files
    files = client.get("/api/v1/sandbox/files")
    assert files.status_code == 200
    assert "files" in files.json()

    # 8. Sandbox Outbox
    outbox = client.get("/api/v1/sandbox/outbox")
    assert outbox.status_code == 200
    assert "emails" in outbox.json()

    # 9. Sandbox Network Logs
    net = client.get("/api/v1/sandbox/network-logs")
    assert net.status_code == 200
    assert "network_logs" in net.json()
