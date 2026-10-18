"""Tests for Phase 7: Reproducible Demo Scenarios & Evaluation Metrics."""
import pytest
from fastapi.testclient import TestClient

from app.evaluation import evaluation_engine
from app.main import app


@pytest.fixture
def client() -> TestClient:
    """FastAPI TestClient fixture."""
    return TestClient(app)


def test_sequential_demo_scenarios_all_pass() -> None:
    """Verify all 7 demonstration scenarios execute sequentially with expected decisions."""
    step_results = evaluation_engine.run_sequential_demo()

    assert len(step_results) == 7

    # Scenario 1: Legitimate read of allowed file -> ALLOW
    s1 = step_results[0]
    assert s1.step_number == 1
    assert s1.expected_decision == "ALLOW"
    assert s1.actual_decision == "ALLOW"
    assert s1.match is True
    assert s1.status == "EXECUTED"

    # Scenario 2: Attempt to read restricted file -> BLOCK
    s2 = step_results[1]
    assert s2.step_number == 2
    assert s2.expected_decision == "BLOCK"
    assert s2.actual_decision == "BLOCK"
    assert s2.match is True
    assert s2.status == "BLOCKED"

    # Scenario 3: Attempt to use unknown tool -> BLOCK
    s3 = step_results[2]
    assert s3.step_number == 3
    assert s3.expected_decision == "BLOCK"
    assert s3.actual_decision == "BLOCK"
    assert s3.match is True
    assert s3.status == "BLOCKED"

    # Scenario 4: Attempt to send to disallowed destination -> BLOCK
    s4 = step_results[3]
    assert s4.step_number == 4
    assert s4.expected_decision == "BLOCK"
    assert s4.actual_decision == "BLOCK"
    assert s4.match is True
    assert s4.status == "BLOCKED"

    # Scenario 5: Action requiring human approval -> REQUIRE_APPROVAL until approved
    s5 = step_results[4]
    assert s5.step_number == 5
    assert s5.expected_decision == "REQUIRE_APPROVAL"
    assert s5.actual_decision == "REQUIRE_APPROVAL"
    assert s5.match is True
    assert s5.status == "APPROVED_EXECUTED"

    # Scenario 6: Access to synthetic canary value -> ALLOW + Security Finding
    s6 = step_results[5]
    assert s6.step_number == 6
    assert s6.expected_decision == "ALLOW"
    assert s6.actual_decision == "ALLOW"
    assert s6.match is True
    assert s6.canary_findings_count >= 1

    # Scenario 7: Benign-looking instruction proposing unauthorized call -> BLOCK
    s7 = step_results[6]
    assert s7.step_number == 7
    assert s7.expected_decision == "BLOCK"
    assert s7.actual_decision == "BLOCK"
    assert s7.match is True
    assert s7.status == "BLOCKED"


def test_empirical_evaluation_metrics_rigor() -> None:
    """Verify evaluation engine computes empirical metrics with zero-division safety."""
    report = evaluation_engine.run_evaluation()

    assert "metrics" in report
    assert "denominators" in report
    metrics = report["metrics"]
    denoms = report["denominators"]

    # 1. Unauthorized block rate must be 100% (all threats caught)
    assert metrics["unauthorized_call_block_rate_percent"] == 100.0
    assert denoms["unauthorized_blocked"] == denoms["unauthorized_total"]
    assert denoms["unauthorized_total"] > 0

    # 2. Legitimate action false block rate must be 0.0% (no false positives)
    assert metrics["legitimate_action_false_block_rate_percent"] == 0.0
    assert denoms["legitimate_blocked"] == 0
    assert denoms["legitimate_total"] > 0

    # 3. Canary detection precision and recall
    assert metrics["canary_detection_precision_percent"] == 100.0
    assert metrics["canary_detection_recall_percent"] == 100.0
    assert denoms["canary_true_positives"] > 0

    # 4. Audit completeness must be 100.0% (every request audited)
    assert metrics["audit_record_completeness_percent"] == 100.0
    assert denoms["total_audited_calls"] == report["total_test_cases"]


def test_api_evaluation_demo_endpoint(client: TestClient) -> None:
    """POST /api/v1/evaluation/demo executes 7 scenarios and returns valid response."""
    res = client.post("/api/v1/evaluation/demo")
    assert res.status_code == 200
    data = res.json()

    assert data["total_steps"] == 7
    assert data["all_matched"] is True
    assert len(data["steps"]) == 7

    # Check that steps are 1-indexed and in sequence
    for i, step in enumerate(data["steps"], start=1):
        assert step["step_number"] == i
        assert step["match"] is True
        assert len(step["rule_id"]) > 0


def test_api_evaluation_run_endpoint(client: TestClient) -> None:
    """POST /api/v1/evaluation/run returns empirical evaluation report."""
    res = client.post("/api/v1/evaluation/run")
    assert res.status_code == 200
    data = res.json()

    assert data["total_test_cases"] >= 14
    assert data["metrics"]["unauthorized_call_block_rate_percent"] == 100.0
    assert data["metrics"]["legitimate_action_false_block_rate_percent"] == 0.0
    assert data["metrics"]["audit_record_completeness_percent"] == 100.0
    assert len(data["test_details"]) == data["total_test_cases"]
