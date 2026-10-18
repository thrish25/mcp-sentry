"""Isolated Mock Tool Sandbox for MCP-Sentry.

Security Constraints Enforced:
- Operates strictly on a synthetic dataset; never touches the real host filesystem.
- Never sends external network traffic or uses SMTP/sockets.
- Never invokes subprocesses or executes real host shell commands.
- Only callable through the authorized ExecutionService.
"""
from typing import Any
from app.database import Database, db as default_db


class MockSandbox:
    """Isolated sandbox executing mock tool operations safely on synthetic data."""

    def __init__(self, database: Database | None = None) -> None:
        self.db = database or default_db

    def read_file(self, path: str) -> dict[str, Any]:
        """Read harmless sample file content strictly from the synthetic store."""
        content = self.db.get_synthetic_file(path)
        if content is None:
            raise FileNotFoundError(f"Synthetic file '{path}' not found in sandbox dataset.")
        return {
            "path": path,
            "content": content,
            "size_bytes": len(content),
            "source": "synthetic_file_store",
        }

    def write_file(self, path: str, content: str) -> dict[str, Any]:
        """Write content strictly into the synthetic file store."""
        self.db.write_synthetic_file(path, content, is_scratch=True)
        return {
            "path": path,
            "bytes_written": len(content),
            "status": "saved_to_synthetic_sandbox",
        }

    def search_kb(self, query: str) -> dict[str, Any]:
        """Return simulated knowledge base search results."""
        return {
            "query": query,
            "matches": [
                {
                    "title": "IBM Z Security Gateway Architecture",
                    "snippet": "MCP-Sentry provides zero-trust arbitration for autonomous AI tool invocations.",
                    "score": 0.98,
                },
                {
                    "title": "Model Context Protocol Boundary Rules",
                    "snippet": "Default-deny policy enforcement prevents prompt-injection escapes.",
                    "score": 0.91,
                },
            ],
            "total_matches": 2,
        }

    def query_metrics(self, metric_name: str) -> dict[str, Any]:
        """Return simulated telemetry metrics."""
        return {
            "metric_name": metric_name,
            "value": 12.8,
            "unit": "ms" if "latency" in metric_name.lower() else "count",
            "source": "ibm_z_synthetic_telemetry",
        }

    def fetch_url(
        self,
        url: str,
        request_id: str,
        method: str = "GET",
        payload: str | None = None,
    ) -> dict[str, Any]:
        """Record simulated network request and return mock response without network I/O."""
        simulated_response = '{"service": "internal-mock-service", "status": "healthy"}'
        log_id = self.db.insert_network_log(
            request_id=request_id,
            url=url,
            method=method,
            payload=payload,
            status_code=200,
            response_body=simulated_response,
        )
        return {
            "status_code": 200,
            "url": url,
            "simulated": True,
            "network_log_id": log_id,
            "data": {"service": "internal-mock-service", "status": "healthy"},
        }

    def send_email(
        self,
        to: str,
        subject: str,
        body: str,
        request_id: str,
    ) -> dict[str, Any]:
        """Record simulated outgoing email into the fake outbox without SMTP."""
        outbox_id = self.db.insert_email(
            request_id=request_id,
            to_address=to,
            subject=subject,
            body=body,
        )
        return {
            "status": "queued_locally",
            "outbox_id": outbox_id,
            "to": to,
            "subject": subject,
            "simulated": True,
        }

    def execute_command(self, command: str) -> dict[str, Any]:
        """Simulate command output safely without invoking any subprocess or host shell."""
        normalized = command.strip().lower()
        if normalized.startswith("echo"):
            simulated_stdout = command.strip()[4:].strip().strip("'\"") + "\n"
        elif normalized in ("ls", "dir"):
            simulated_stdout = "data/\nscratch/\n"
        elif normalized in ("whoami", "id"):
            simulated_stdout = "z_sandbox_user (uid=1001, gid=1001)\n"
        else:
            simulated_stdout = f"[mock-exec] Command executed in container: '{command}'\n"

        return {
            "command": command,
            "simulated_stdout": simulated_stdout,
            "exit_code": 0,
            "simulated": True,
        }

    def database_migration(self, migration_id: str) -> dict[str, Any]:
        """Simulate schema migration."""
        return {
            "migration_id": migration_id,
            "status": "applied_mock",
            "target": "synthetic_schema_v2",
        }

    def restart_service(self, service_name: str) -> dict[str, Any]:
        """Simulate service restart."""
        return {
            "service_name": service_name,
            "status": "restarted_mock",
            "uptime_seconds": 0,
        }
