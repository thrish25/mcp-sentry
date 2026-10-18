"""Test suite for MCP-Sentry health and root endpoints."""
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_health_check() -> None:
    """Validate /health endpoint returns healthy status and service metadata."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["service"] == "mcp-sentry-backend"
    assert "version" in data
    assert "environment" in data


def test_root_endpoint() -> None:
    """Validate root endpoint responds with online status and documentation link."""
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "online"
    assert "docs_url" in data
