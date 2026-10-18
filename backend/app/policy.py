"""Deterministic Policy Engine for MCP-Sentry Runtime Security Gateway."""
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import PurePosixPath, PureWindowsPath
from typing import Any, Callable

from app.schemas import DecisionEnum, PolicyDecision, ToolCall

# Path traversal detection patterns
PATH_TRAVERSAL_PATTERN = re.compile(
    r"(\.\.[/\\])|([/\\]\.\.)|(\.\.$)|(%2e%2e)|(%252e%252e)|(\x00)",
    re.IGNORECASE,
)

# Forbidden sensitive paths
SENSITIVE_PATHS = [
    "/etc",
    "/proc",
    "/sys",
    "/root",
    "~/.ssh",
    ".ssh",
    ".env",
    "c:\\windows",
    "c:/windows",
    "windows/system32",
]

# High-risk command patterns
DANGEROUS_COMMAND_PATTERN = re.compile(
    r"\b(rm\s+-rf|rmdir\s+/s|format|mkfs|dd|sudo|chmod\s+777|curl|wget|powershell|bash|sh|net\s+user|del\s+/f)\b",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class ToolPolicy:
    """Security policy definition for an authorized MCP tool."""

    name: str
    allowed_destinations: list[str]
    required_arguments: list[str]
    argument_validator: Callable[[dict[str, Any]], tuple[bool, str, str]] | None = None
    requires_approval: bool = False
    approval_rule_id: str = "RULE-REQUIRE-APPROVAL"
    allow_rule_id: str = "RULE-ALLOW-TOOL"


def _is_sensitive_path(normalized: str) -> bool:
    """Check if normalized path targets system-sensitive directories or files."""
    segments = [p for p in normalized.strip("/").split("/") if p]
    sensitive_dirs = {"etc", "proc", "sys", "root", ".ssh"}
    # Any directory segment in sensitive dirs
    if any(s in sensitive_dirs for s in segments[:-1]):
        return True
    # Target file or directory name is sensitive
    if segments and (segments[-1] in sensitive_dirs or segments[-1] == ".env" or segments[-1].endswith(".env")):
        return True
    if "windows/system32" in normalized or "c:/windows" in normalized or "~/.ssh" in normalized:
        return True
    return False


def _validate_read_file(args: dict[str, Any]) -> tuple[bool, str, str]:
    """Validate arguments and file path for read_file operations."""
    path_val = args.get("path")
    if not isinstance(path_val, str) or not path_val.strip():
        return False, "RULE-INVALID-ARGUMENTS", "Argument 'path' must be a non-empty string."

    # Path traversal detection
    if PATH_TRAVERSAL_PATTERN.search(path_val) or ".." in path_val:
        return False, "RULE-PATH-TRAVERSAL", f"Path traversal attempt rejected in path: '{path_val}'"

    # Normalize path checking
    normalized = path_val.replace("\\", "/").lower()
    if _is_sensitive_path(normalized):
        return False, "RULE-UNAUTHORIZED-PATH", f"Access to sensitive path denied: '{path_val}'"

    # Enforce allowed directory boundaries
    allowed_roots = ("/workspace", "workspace/", "sandbox/", "/sandbox", "data/", "/data")
    if not any(normalized.startswith(root) for root in allowed_roots):
        return (
            False,
            "RULE-UNAUTHORIZED-PATH",
            f"Path '{path_val}' is outside authorized sandbox roots: {allowed_roots}",
        )

    return True, "", ""


def _validate_write_file(args: dict[str, Any]) -> tuple[bool, str, str]:
    """Validate arguments and path for write_file operations."""
    path_val = args.get("path")
    content_val = args.get("content")

    if not isinstance(path_val, str) or not path_val.strip():
        return False, "RULE-INVALID-ARGUMENTS", "Argument 'path' must be a non-empty string."

    if not isinstance(content_val, str):
        return False, "RULE-INVALID-ARGUMENTS", "Argument 'content' must be a string."

    # Path traversal detection
    if PATH_TRAVERSAL_PATTERN.search(path_val) or ".." in path_val:
        return False, "RULE-PATH-TRAVERSAL", f"Path traversal attempt rejected in path: '{path_val}'"

    normalized = path_val.replace("\\", "/").lower()
    if _is_sensitive_path(normalized):
        return False, "RULE-UNAUTHORIZED-PATH", f"Access to sensitive path denied: '{path_val}'"

    # Only scratch paths are permitted for writing
    allowed_write_roots = ("/workspace/scratch", "workspace/scratch/", "sandbox/scratch/", "/sandbox/scratch")
    if not any(normalized.startswith(root) for root in allowed_write_roots):
        # Modification outside scratch directory requires explicit approval
        return False, "RULE-REQUIRE-APPROVAL-WRITE", f"Write operation to '{path_val}' requires supervisor approval."

    return True, "", ""


def _validate_execute_command(args: dict[str, Any]) -> tuple[bool, str, str]:
    """Validate command argument and block dangerous shell operations."""
    command_val = args.get("command")
    if not isinstance(command_val, str) or not command_val.strip():
        return False, "RULE-INVALID-ARGUMENTS", "Argument 'command' must be a non-empty string."

    if DANGEROUS_COMMAND_PATTERN.search(command_val):
        return (
            False,
            "RULE-DANGEROUS-COMMAND",
            f"Command execution blocked due to dangerous command pattern in: '{command_val}'",
        )

    # Shell chaining injection checks
    if any(token in command_val for token in (";", "&&", "||", "|", "`", "$(")):
        return (
            False,
            "RULE-DANGEROUS-COMMAND",
            f"Command execution blocked due to shell chaining or subshell syntax in: '{command_val}'",
        )

    return True, "", ""


def _validate_search_kb(args: dict[str, Any]) -> tuple[bool, str, str]:
    """Validate search_kb arguments."""
    query = args.get("query")
    if not isinstance(query, str) or not query.strip():
        return False, "RULE-INVALID-ARGUMENTS", "Argument 'query' must be a non-empty string."
    if len(query) > 1000:
        return False, "RULE-INVALID-ARGUMENTS", "Query length exceeds maximum limit of 1000 characters."
    return True, "", ""


def _validate_query_metrics(args: dict[str, Any]) -> tuple[bool, str, str]:
    """Validate query_metrics arguments."""
    metric = args.get("metric_name")
    if not isinstance(metric, str) or not metric.strip():
        return False, "RULE-INVALID-ARGUMENTS", "Argument 'metric_name' must be a non-empty string."
    return True, "", ""


def _validate_send_email(args: dict[str, Any]) -> tuple[bool, str, str]:
    """Validate send_email arguments."""
    to_val = args.get("to")
    subject_val = args.get("subject")
    body_val = args.get("body")

    if not isinstance(to_val, str) or "@" not in to_val or not to_val.strip():
        return False, "RULE-INVALID-ARGUMENTS", "Argument 'to' must be a valid email address string."
    if not isinstance(subject_val, str) or not subject_val.strip():
        return False, "RULE-INVALID-ARGUMENTS", "Argument 'subject' must be a non-empty string."
    if not isinstance(body_val, str):
        return False, "RULE-INVALID-ARGUMENTS", "Argument 'body' must be a string."

    return True, "", ""


def _validate_fetch_url(args: dict[str, Any]) -> tuple[bool, str, str]:
    """Validate fetch_url to ensure only authorized internal simulated endpoints are accessed."""
    url_val = args.get("url")
    if not isinstance(url_val, str) or not url_val.strip():
        return False, "RULE-INVALID-ARGUMENTS", "Argument 'url' must be a non-empty string."

    allowed_prefixes = (
        "http://internal/",
        "https://internal.ibm.z/",
        "http://mock-service/",
        "http://sandbox/",
    )
    normalized = url_val.lower()
    if not any(normalized.startswith(prefix) for prefix in allowed_prefixes):
        return (
            False,
            "RULE-UNAUTHORIZED-URL",
            f"Access to external or unapproved URL '{url_val}' is prohibited. Allowed prefixes: {allowed_prefixes}",
        )

    return True, "", ""


# Explicit Permission Catalog (Default-Deny for any tool not listed)
PERMISSION_CATALOG: dict[str, ToolPolicy] = {
    "read_file": ToolPolicy(
        name="read_file",
        allowed_destinations=["local-sandbox", "fs-server"],
        required_arguments=["path"],
        argument_validator=_validate_read_file,
        allow_rule_id="RULE-ALLOW-READ-FILE",
    ),
    "write_file": ToolPolicy(
        name="write_file",
        allowed_destinations=["local-sandbox", "fs-server"],
        required_arguments=["path", "content"],
        argument_validator=_validate_write_file,
        allow_rule_id="RULE-ALLOW-WRITE-FILE",
    ),
    "search_kb": ToolPolicy(
        name="search_kb",
        allowed_destinations=["mcp-knowledge-server", "local-sandbox"],
        required_arguments=["query"],
        argument_validator=_validate_search_kb,
        allow_rule_id="RULE-ALLOW-SEARCH-KB",
    ),
    "query_metrics": ToolPolicy(
        name="query_metrics",
        allowed_destinations=["metrics-service", "local-sandbox"],
        required_arguments=["metric_name"],
        argument_validator=_validate_query_metrics,
        allow_rule_id="RULE-ALLOW-METRICS",
    ),
    "fetch_url": ToolPolicy(
        name="fetch_url",
        allowed_destinations=["internal-api-gateway", "local-sandbox"],
        required_arguments=["url"],
        argument_validator=_validate_fetch_url,
        allow_rule_id="RULE-ALLOW-FETCH-URL",
    ),
    "send_email": ToolPolicy(
        name="send_email",
        allowed_destinations=["mail-gateway", "local-sandbox"],
        required_arguments=["to", "subject", "body"],
        argument_validator=_validate_send_email,
        requires_approval=True,
        approval_rule_id="RULE-REQUIRE-APPROVAL-EMAIL",
        allow_rule_id="RULE-ALLOW-EMAIL",
    ),
    "execute_command": ToolPolicy(
        name="execute_command",
        allowed_destinations=["isolated-runner"],
        required_arguments=["command"],
        argument_validator=_validate_execute_command,
        requires_approval=True,
        approval_rule_id="RULE-REQUIRE-APPROVAL-EXEC",
        allow_rule_id="RULE-ALLOW-EXEC",
    ),
    "database_migration": ToolPolicy(
        name="database_migration",
        allowed_destinations=["db-server"],
        required_arguments=["migration_id"],
        requires_approval=True,
        approval_rule_id="RULE-REQUIRE-APPROVAL-DB-MIGRATE",
        allow_rule_id="RULE-ALLOW-DB-MIGRATE",
    ),
    "restart_service": ToolPolicy(
        name="restart_service",
        allowed_destinations=["ops-controller"],
        required_arguments=["service_name"],
        requires_approval=True,
        approval_rule_id="RULE-REQUIRE-APPROVAL-RESTART",
        allow_rule_id="RULE-ALLOW-RESTART",
    ),
}


class PolicyEngine:
    """Deterministic security engine arbitrating tool calls."""

    @staticmethod
    def evaluate(tool_call: ToolCall) -> PolicyDecision:
        """Evaluate an inbound ToolCall against security policies and render a decision.

        Order of evaluation:
        1. Default-Deny unknown tools
        2. Unauthorized destination rejection
        3. Required arguments validation
        4. Tool-specific argument & path validation
        5. Approval-required operations check
        6. Allowed operation confirmation
        """
        now_iso = datetime.now(timezone.utc).isoformat()
        decision_id = f"dec-{uuid.uuid4().hex[:12]}"

        # 1. Default-Deny: Unknown tools
        policy = PERMISSION_CATALOG.get(tool_call.tool_name)
        if policy is None:
            return PolicyDecision(
                decision_id=decision_id,
                request_id=tool_call.request_id,
                decision=DecisionEnum.BLOCK,
                rule_id="RULE-DEFAULT-DENY",
                reason=f"Tool '{tool_call.tool_name}' is not in the authorized permissions catalog.",
                timestamp=now_iso,
            )

        # 2. Destination authorization check
        if tool_call.destination not in policy.allowed_destinations:
            return PolicyDecision(
                decision_id=decision_id,
                request_id=tool_call.request_id,
                decision=DecisionEnum.BLOCK,
                rule_id="RULE-UNAUTHORIZED-DESTINATION",
                reason=(
                    f"Destination '{tool_call.destination}' is not authorized for tool '{tool_call.tool_name}'. "
                    f"Authorized destinations: {policy.allowed_destinations}"
                ),
                timestamp=now_iso,
            )

        # 3. Required arguments check
        missing_args = [arg for arg in policy.required_arguments if arg not in tool_call.arguments]
        if missing_args:
            return PolicyDecision(
                decision_id=decision_id,
                request_id=tool_call.request_id,
                decision=DecisionEnum.BLOCK,
                rule_id="RULE-INVALID-ARGUMENTS",
                reason=f"Missing required argument(s) for tool '{tool_call.tool_name}': {missing_args}",
                timestamp=now_iso,
            )

        # 4. Tool-specific argument & path validator
        if policy.argument_validator is not None:
            is_valid, rule_id, failure_reason = policy.argument_validator(tool_call.arguments)
            if not is_valid:
                # Some validations might request approval rather than an outright block
                if rule_id.startswith("RULE-REQUIRE-APPROVAL"):
                    return PolicyDecision(
                        decision_id=decision_id,
                        request_id=tool_call.request_id,
                        decision=DecisionEnum.REQUIRE_APPROVAL,
                        rule_id=rule_id,
                        reason=failure_reason,
                        timestamp=now_iso,
                    )
                return PolicyDecision(
                    decision_id=decision_id,
                    request_id=tool_call.request_id,
                    decision=DecisionEnum.BLOCK,
                    rule_id=rule_id,
                    reason=failure_reason,
                    timestamp=now_iso,
                )

        # 5. Approval-required operations check
        if policy.requires_approval:
            return PolicyDecision(
                decision_id=decision_id,
                request_id=tool_call.request_id,
                decision=DecisionEnum.REQUIRE_APPROVAL,
                rule_id=policy.approval_rule_id,
                reason=f"Tool '{tool_call.tool_name}' requires human approval before execution.",
                timestamp=now_iso,
            )

        # 6. Allow operation
        return PolicyDecision(
            decision_id=decision_id,
            request_id=tool_call.request_id,
            decision=DecisionEnum.ALLOW,
            rule_id=policy.allow_rule_id,
            reason=f"Tool call '{tool_call.tool_name}' successfully verified and authorized.",
            timestamp=now_iso,
        )
