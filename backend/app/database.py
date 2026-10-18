"""SQLite database layer for MCP-Sentry audit ledger, security findings, and synthetic tool sandbox."""
import json
import math
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.canary import SYNTHETIC_CANARIES
from app.config import get_settings

# Thread-local storage for sqlite connections
_local = threading.local()


def _get_db_path() -> str:
    """Resolve database path from application settings."""
    settings = get_settings()
    url = settings.database_url
    if url.startswith("sqlite:///"):
        return url.replace("sqlite:///", "")
    return "mcp_sentry.db"


class Database:
    """Thread-safe SQLite database manager for audit records, findings, and mock data."""

    def __init__(self, db_path: str | None = None) -> None:
        self.db_path = db_path or _get_db_path()
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        """Return a thread-local SQLite connection with dictionary row access and WAL mode."""
        conn = getattr(_local, "connection", None)
        if conn is None:
            conn = sqlite3.connect(self.db_path, timeout=15.0, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode = WAL;")
            conn.execute("PRAGMA busy_timeout = 15000;")
            _local.connection = conn
        return conn

    def _init_db(self) -> None:
        """Create tables if they do not exist and seed synthetic files & canaries."""
        conn = sqlite3.connect(self.db_path, timeout=15.0, check_same_thread=False)
        try:
            conn.execute("PRAGMA journal_mode = WAL;")
            conn.execute("PRAGMA busy_timeout = 15000;")
            cursor = conn.cursor()
            cursor.executescript(
                """
                CREATE TABLE IF NOT EXISTS audit_records (
                    request_id TEXT PRIMARY KEY,
                    decision_id TEXT NOT NULL,
                    tool_name TEXT NOT NULL,
                    origin TEXT NOT NULL,
                    destination TEXT NOT NULL,
                    arguments_json TEXT NOT NULL,
                    decision TEXT NOT NULL,
                    rule_id TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    status TEXT NOT NULL,
                    result_json TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS security_findings (
                    finding_id TEXT PRIMARY KEY,
                    request_id TEXT NOT NULL,
                    decision_id TEXT NOT NULL,
                    canary_token TEXT NOT NULL,
                    canary_name TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    evidence TEXT NOT NULL,
                    tool_name TEXT NOT NULL,
                    origin TEXT NOT NULL,
                    destination TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS approval_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    request_id TEXT NOT NULL,
                    decision_id TEXT NOT NULL,
                    approver TEXT NOT NULL,
                    approved INTEGER NOT NULL,
                    reason TEXT,
                    status_before TEXT NOT NULL DEFAULT 'PENDING_APPROVAL',
                    status_after TEXT NOT NULL DEFAULT 'RESOLVED',
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS canary_tokens (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    token_value TEXT UNIQUE NOT NULL,
                    name TEXT NOT NULL,
                    file_path TEXT NOT NULL,

                    severity TEXT NOT NULL,
                    description TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS fake_email_outbox (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    request_id TEXT NOT NULL,
                    to_address TEXT NOT NULL,
                    subject TEXT NOT NULL,
                    body TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS fake_network_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    request_id TEXT NOT NULL,
                    url TEXT NOT NULL,
                    method TEXT NOT NULL,
                    payload TEXT,
                    status_code INTEGER NOT NULL,
                    response_body TEXT,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS synthetic_files (
                    path TEXT PRIMARY KEY,
                    content TEXT NOT NULL,
                    is_scratch INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                """
            )
            conn.commit()
            self._seed_synthetic_files_and_canaries(conn)
        finally:
            conn.close()

    def _seed_synthetic_files_and_canaries(self, conn: sqlite3.Connection) -> None:
        """Seed harmless synthetic files embedded with canary tokens."""
        now_iso = datetime.now(timezone.utc).isoformat()
        cursor = conn.cursor()

        # 1. Seed or update synthetic files with canary tokens
        sample_files = [
            (
                "/workspace/data/system_info.json",
                json.dumps(
                    {
                        "system": "IBM Z Mainframe Virtual Partition",
                        "architecture": "s390x",
                        "os": "z/OS Container Extensions (zCX)",
                        "security_level": "EAL5+",
                        "diagnostic_canary": "CANARY-IBMZ-SEC-KEY-9941",
                        "status": "nominal",
                    },
                    indent=2,
                ),
                0,
                now_iso,
                now_iso,
            ),
            (
                "/workspace/data/security_report.txt",
                (
                    "IBM Z Datathon - MCP-Sentry Security Status Report\n"
                    "Audit Status: All MCP tool invocations are arbitrated by Runtime Gateway.\n"
                    "Audit verification canary: CANARY-TOKEN-VAULT-7712\n"
                    "Anomalies Detected: 0\n"
                    "Zero-Trust Perimeter: Enforced\n"
                ),
                0,
                now_iso,
                now_iso,
            ),
            (
                "/workspace/data/user_directory.csv",
                (
                    "id,username,department,role,canary_field\n"
                    "101,z_analyst,Security,Viewer,none\n"
                    "102,z_operator,Infrastructure,Operator,none\n"
                    "103,z_auditor,Compliance,Auditor,none\n"
                    "999,canary_admin,Security,SuperUser,CANARY-LEAK-PAYLOAD-3301\n"
                ),
                0,
                now_iso,
                now_iso,
            ),
            (
                "/workspace/scratch/sample.txt",
                "Harmless scratch workspace buffer for temporary tool calculations.\n",
                1,
                now_iso,
                now_iso,
            ),
        ]

        cursor.executemany(
            """
            INSERT INTO synthetic_files (path, content, is_scratch, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(path) DO UPDATE SET
                content = excluded.content,
                updated_at = excluded.updated_at
            """,
            sample_files,
        )

        # 2. Seed registered canary token metadata
        for c in SYNTHETIC_CANARIES:
            cursor.execute(
                """
                INSERT OR IGNORE INTO canary_tokens (token_value, name, file_path, severity, description, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (c.token_value, c.name, c.file_path, c.severity, c.description, now_iso),
            )
        conn.commit()

    # ------------------------------------------------------------------------
    # Audit Records
    # ------------------------------------------------------------------------
    def insert_audit_record(
        self,
        request_id: str,
        decision_id: str,
        tool_name: str,
        origin: str,
        destination: str,
        arguments: dict[str, Any],
        decision: str,
        rule_id: str,
        reason: str,
        status: str,
        result: dict[str, Any] | None = None,
    ) -> None:
        """Insert or replace a tool call into the audit ledger."""
        conn = self._get_connection()
        now_iso = datetime.now(timezone.utc).isoformat()
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO audit_records (
                request_id, decision_id, tool_name, origin, destination,
                arguments_json, decision, rule_id, reason, status, result_json,
                created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(request_id) DO UPDATE SET
                decision_id = excluded.decision_id,
                tool_name = excluded.tool_name,
                origin = excluded.origin,
                destination = excluded.destination,
                arguments_json = excluded.arguments_json,
                decision = excluded.decision,
                rule_id = excluded.rule_id,
                reason = excluded.reason,
                status = excluded.status,
                result_json = excluded.result_json,
                updated_at = excluded.updated_at
            """,
            (
                request_id,
                decision_id,
                tool_name,
                origin,
                destination,
                json.dumps(arguments),
                decision,
                rule_id,
                reason,
                status,
                json.dumps(result) if result is not None else None,
                now_iso,
                now_iso,
            ),
        )
        conn.commit()

    def update_audit_status(
        self,
        request_id: str,
        status: str,
        result: dict[str, Any] | None = None,
    ) -> bool:
        """Update the execution status and output of an existing audit record."""
        conn = self._get_connection()
        now_iso = datetime.now(timezone.utc).isoformat()
        cursor = conn.cursor()
        cursor.execute(
            """
            UPDATE audit_records
            SET status = ?, result_json = ?, updated_at = ?
            WHERE request_id = ?
            """,
            (
                status,
                json.dumps(result) if result is not None else None,
                now_iso,
                request_id,
            ),
        )
        conn.commit()
        return cursor.rowcount > 0

    def get_audit_record(self, request_id: str) -> dict[str, Any] | None:
        """Retrieve an audit record by request ID."""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM audit_records WHERE request_id = ?", (request_id,))
        row = cursor.fetchone()
        if not row:
            return None
        d = dict(row)
        d["arguments"] = json.loads(d["arguments_json"])
        d["result"] = json.loads(d["result_json"]) if d["result_json"] else None
        return d

    def list_audit_records(self, limit: int = 100) -> list[dict[str, Any]]:
        """List audit records ordered by most recent first."""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM audit_records ORDER BY created_at DESC LIMIT ?",
            (limit,),
        )
        records = []
        for row in cursor.fetchall():
            d = dict(row)
            d["arguments"] = json.loads(d["arguments_json"])
            d["result"] = json.loads(d["result_json"]) if d["result_json"] else None
            records.append(d)
        return records

    def list_audit_records_paginated(
        self,
        page: int = 1,
        page_size: int = 20,
        decision: str | None = None,
        status: str | None = None,
        tool_name: str | None = None,
    ) -> dict[str, Any]:
        """Return paginated audit records with optional filtering."""
        conn = self._get_connection()
        cursor = conn.cursor()

        conditions: list[str] = []
        params: list[Any] = []

        if decision:
            conditions.append("decision = ?")
            params.append(decision.upper())
        if status:
            conditions.append("status = ?")
            params.append(status.upper())
        if tool_name:
            conditions.append("tool_name = ?")
            params.append(tool_name)

        where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""

        # Total count
        cursor.execute(f"SELECT COUNT(*) FROM audit_records {where_clause}", params)
        total = cursor.fetchone()[0]

        # Paginated fetch
        offset = (page - 1) * page_size
        query_params = list(params) + [page_size, offset]
        cursor.execute(
            f"SELECT * FROM audit_records {where_clause} ORDER BY created_at DESC LIMIT ? OFFSET ?",
            query_params,
        )

        items = []
        for row in cursor.fetchall():
            d = dict(row)
            d["arguments"] = json.loads(d["arguments_json"])
            d["result"] = json.loads(d["result_json"]) if d["result_json"] else None
            items.append(d)

        total_pages = math.ceil(total / page_size) if total > 0 else 1
        return {
            "items": items,
            "total": total,
            "page": page,
            "page_size": page_size,
            "total_pages": total_pages,
        }

    def get_recent_decisions(self, limit: int = 10) -> list[dict[str, Any]]:
        """Return recent decisions linking request_id and decision_id."""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT request_id, decision_id, tool_name, origin, destination,
                   decision, rule_id, reason, status, created_at
            FROM audit_records
            ORDER BY created_at DESC
            LIMIT ?
            """,
            (limit,),
        )
        return [dict(row) for row in cursor.fetchall()]

    # ------------------------------------------------------------------------
    # Security Findings & Canary Events
    # ------------------------------------------------------------------------
    def insert_security_finding(
        self,
        request_id: str,
        decision_id: str,
        canary_token: str,
        canary_name: str,
        event_type: str,
        severity: str,
        evidence: str,
        tool_name: str,
        origin: str,
        destination: str,
    ) -> str:
        """Record an investigation finding when a canary token is touched or exfiltrated."""
        conn = self._get_connection()
        finding_id = f"find-{uuid.uuid4().hex[:10]}"
        now_iso = datetime.now(timezone.utc).isoformat()
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO security_findings (
                finding_id, request_id, decision_id, canary_token, canary_name,
                event_type, severity, evidence, tool_name, origin, destination, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                finding_id,
                request_id,
                decision_id,
                canary_token,
                canary_name,
                event_type,
                severity,
                evidence,
                tool_name,
                origin,
                destination,
                now_iso,
            ),
        )
        conn.commit()
        return finding_id

    def list_security_findings(
        self,
        page: int = 1,
        page_size: int = 20,
        severity: str | None = None,
        event_type: str | None = None,
    ) -> dict[str, Any]:
        """Return paginated security findings."""
        conn = self._get_connection()
        cursor = conn.cursor()

        conditions: list[str] = []
        params: list[Any] = []

        if severity:
            conditions.append("severity = ?")
            params.append(severity.upper())
        if event_type:
            conditions.append("event_type = ?")
            params.append(event_type.upper())

        where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""

        cursor.execute(f"SELECT COUNT(*) FROM security_findings {where_clause}", params)
        total = cursor.fetchone()[0]

        offset = (page - 1) * page_size
        query_params = list(params) + [page_size, offset]
        cursor.execute(
            f"SELECT * FROM security_findings {where_clause} ORDER BY created_at DESC LIMIT ? OFFSET ?",
            query_params,
        )

        items = [dict(row) for row in cursor.fetchall()]
        total_pages = math.ceil(total / page_size) if total > 0 else 1
        return {
            "items": items,
            "total": total,
            "page": page,
            "page_size": page_size,
            "total_pages": total_pages,
        }

    # ------------------------------------------------------------------------
    # Approval Events
    # ------------------------------------------------------------------------
    def insert_approval_event(
        self,
        request_id: str,
        decision_id: str,
        approver: str,
        approved: bool,
        reason: str = "",
        status_before: str = "PENDING_APPROVAL",
        status_after: str = "RESOLVED",
    ) -> int:
        """Record an explicit human/supervisor authorization action."""
        conn = self._get_connection()
        now_iso = datetime.now(timezone.utc).isoformat()
        cursor = conn.cursor()
        try:
            cursor.execute(
                """
                INSERT INTO approval_events (
                    request_id, decision_id, approver, approved, reason, status_before, status_after, created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    request_id,
                    decision_id,
                    approver,
                    1 if approved else 0,
                    reason,
                    status_before,
                    status_after,
                    now_iso,
                ),
            )
            conn.commit()
            return cursor.lastrowid or 0
        except Exception:
            conn.rollback()
            raise


    def list_approval_events(self, request_id: str | None = None) -> list[dict[str, Any]]:
        """List authorization events."""
        conn = self._get_connection()
        cursor = conn.cursor()
        if request_id:
            cursor.execute(
                "SELECT * FROM approval_events WHERE request_id = ? ORDER BY created_at DESC",
                (request_id,),
            )
        else:
            cursor.execute("SELECT * FROM approval_events ORDER BY created_at DESC")
        return [dict(row) for row in cursor.fetchall()]

    # ------------------------------------------------------------------------
    # Aggregate Metrics & Counts
    # ------------------------------------------------------------------------
    def get_aggregate_counts(self) -> dict[str, Any]:
        """Compute aggregate operational and security metrics."""
        conn = self._get_connection()
        cursor = conn.cursor()

        # Total events
        cursor.execute("SELECT COUNT(*) FROM audit_records")
        total_events = cursor.fetchone()[0]

        # Decisions count
        cursor.execute("SELECT decision, COUNT(*) FROM audit_records GROUP BY decision")
        decisions_map = {row[0]: row[1] for row in cursor.fetchall()}

        # Status count
        cursor.execute("SELECT status, COUNT(*) FROM audit_records GROUP BY status")
        status_map = {row[0]: row[1] for row in cursor.fetchall()}

        # Total findings
        cursor.execute("SELECT COUNT(*) FROM security_findings")
        total_findings = cursor.fetchone()[0]

        # Findings by severity
        cursor.execute("SELECT severity, COUNT(*) FROM security_findings GROUP BY severity")
        severity_map = {row[0]: row[1] for row in cursor.fetchall()}

        # Total emails & network logs
        cursor.execute("SELECT COUNT(*) FROM fake_email_outbox")
        outbox_count = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM fake_network_logs")
        network_logs_count = cursor.fetchone()[0]

        # Active canaries count
        cursor.execute("SELECT COUNT(*) FROM canary_tokens")
        active_canaries_count = cursor.fetchone()[0]

        return {
            "total_events": total_events,
            "allow_count": decisions_map.get("ALLOW", 0),
            "block_count": decisions_map.get("BLOCK", 0),
            "require_approval_count": decisions_map.get("REQUIRE_APPROVAL", 0),
            "executed_count": status_map.get("EXECUTED", 0) + status_map.get("APPROVED_EXECUTED", 0),
            "blocked_count": status_map.get("BLOCKED", 0),
            "pending_approval_count": status_map.get("PENDING_APPROVAL", 0),
            "total_findings": total_findings,
            "findings_by_severity": {
                "CRITICAL": severity_map.get("CRITICAL", 0),
                "HIGH": severity_map.get("HIGH", 0),
                "MEDIUM": severity_map.get("MEDIUM", 0),
            },
            "active_canaries_count": active_canaries_count,
            "fake_outbox_count": outbox_count,
            "fake_network_logs_count": network_logs_count,
        }

    def list_canary_tokens(self) -> list[dict[str, Any]]:
        """List all active synthetic canary tokens."""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM canary_tokens ORDER BY id ASC")
        return [dict(row) for row in cursor.fetchall()]

    # ------------------------------------------------------------------------
    # Fake Email Outbox
    # ------------------------------------------------------------------------
    def insert_email(
        self,
        request_id: str,
        to_address: str,
        subject: str,
        body: str,
    ) -> int:
        """Store a simulated outgoing email into the fake outbox."""
        conn = self._get_connection()
        now_iso = datetime.now(timezone.utc).isoformat()
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO fake_email_outbox (request_id, to_address, subject, body, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (request_id, to_address, subject, body, now_iso),
        )
        conn.commit()
        return cursor.lastrowid or 0

    def list_emails(self, limit: int = 50) -> list[dict[str, Any]]:
        """List simulated emails in the local outbox."""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM fake_email_outbox ORDER BY created_at DESC LIMIT ?", (limit,))
        return [dict(row) for row in cursor.fetchall()]

    # ------------------------------------------------------------------------
    # Fake Network Logs
    # ------------------------------------------------------------------------
    def insert_network_log(
        self,
        request_id: str,
        url: str,
        method: str,
        payload: str | None,
        status_code: int,
        response_body: str,
    ) -> int:
        """Record a simulated network request and response without sending external traffic."""
        conn = self._get_connection()
        now_iso = datetime.now(timezone.utc).isoformat()
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO fake_network_logs (
                request_id, url, method, payload, status_code, response_body, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (request_id, url, method, payload, status_code, response_body, now_iso),
        )
        conn.commit()
        return cursor.lastrowid or 0

    def list_network_logs(self, limit: int = 50) -> list[dict[str, Any]]:
        """List simulated network logs."""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM fake_network_logs ORDER BY created_at DESC LIMIT ?", (limit,))
        return [dict(row) for row in cursor.fetchall()]

    # ------------------------------------------------------------------------
    # Synthetic Files
    # ------------------------------------------------------------------------
    def get_synthetic_file(self, path: str) -> str | None:
        """Retrieve harmless file content strictly from the synthetic dataset."""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT content FROM synthetic_files WHERE path = ?", (path,))
        row = cursor.fetchone()
        return row[0] if row else None

    def write_synthetic_file(self, path: str, content: str, is_scratch: bool = True) -> None:
        """Write or update a file strictly within the synthetic file store."""
        conn = self._get_connection()
        now_iso = datetime.now(timezone.utc).isoformat()
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO synthetic_files (path, content, is_scratch, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(path) DO UPDATE SET
                content = excluded.content,
                updated_at = excluded.updated_at
            """,
            (path, content, 1 if is_scratch else 0, now_iso, now_iso),
        )
        conn.commit()

    def list_synthetic_files(self) -> list[dict[str, Any]]:
        """List all synthetic file metadata."""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT path, is_scratch, updated_at FROM synthetic_files ORDER BY path ASC")
        return [dict(row) for row in cursor.fetchall()]


# Global database instance
db = Database()
