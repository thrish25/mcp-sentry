"""Single Execution Service arbitrating tool calls through PolicyEngine before sandbox execution.

Incorporates synthetic canary detection and security finding logging decoupled from authorization checks.
"""
from typing import Any
from app.canary import CanaryDetector
from app.database import Database, db as default_db
from app.policy import PolicyEngine
from app.sandbox import MockSandbox
from app.schemas import DecisionEnum, ExecutionResponse, ExecutionStatus, PolicyDecision, ToolCall


class ExecutionService:
    """Service enforcing policy gateway checks before delegating to the mock tool sandbox."""

    def __init__(
        self,
        database: Database | None = None,
        sandbox: MockSandbox | None = None,
    ) -> None:
        self.db = database or default_db
        self.sandbox = sandbox or MockSandbox(self.db)

    def execute_tool_call(self, tool_call: ToolCall) -> ExecutionResponse:
        """Arbitrate tool call through PolicyEngine, detect canaries, and execute safely if ALLOWed.

        Guarantees:
        - Every tool call is evaluated by PolicyEngine first.
        - BLOCK decisions never execute mock actions.
        - REQUIRE_APPROVAL actions remain pending until explicit approval.
        - Every outcome is persisted to the audit ledger.
        - Canary detection runs independently as an investigative signal without altering permissions.
        """
        # 1. Evaluate against deterministic policy rules
        decision: PolicyDecision = PolicyEngine.evaluate(tool_call)

        # 2. Canary argument inspection (e.g. attempt to transfer or leak a canary token)
        arg_canaries = CanaryDetector.scan_tool_arguments(tool_call.tool_name, tool_call.arguments)
        for canary, event_type, evidence in arg_canaries:
            self.db.insert_security_finding(
                request_id=tool_call.request_id,
                decision_id=decision.decision_id,
                canary_token=canary.token_value,
                canary_name=canary.name,
                event_type=event_type,
                severity=canary.severity,
                evidence=evidence,
                tool_name=tool_call.tool_name,
                origin=tool_call.origin,
                destination=tool_call.destination,
            )

        # 3. Branch based on policy decision
        if decision.decision == DecisionEnum.BLOCK:
            status = ExecutionStatus.BLOCKED
            result_payload = {
                "executed": False,
                "blocked": True,
                "rule_id": decision.rule_id,
                "reason": decision.reason,
            }
            self.db.insert_audit_record(
                request_id=tool_call.request_id,
                decision_id=decision.decision_id,
                tool_name=tool_call.tool_name,
                origin=tool_call.origin,
                destination=tool_call.destination,
                arguments=tool_call.arguments,
                decision=decision.decision.value,
                rule_id=decision.rule_id,
                reason=decision.reason,
                status=status.value,
                result=result_payload,
            )
            return ExecutionResponse(
                request_id=tool_call.request_id,
                decision=decision,
                executed=False,
                status=status,
                error=decision.reason,
                message=f"Action blocked by policy rule '{decision.rule_id}'.",
            )

        if decision.decision == DecisionEnum.REQUIRE_APPROVAL:
            status = ExecutionStatus.PENDING_APPROVAL
            result_payload = {
                "executed": False,
                "pending": True,
                "rule_id": decision.rule_id,
                "reason": decision.reason,
            }
            self.db.insert_audit_record(
                request_id=tool_call.request_id,
                decision_id=decision.decision_id,
                tool_name=tool_call.tool_name,
                origin=tool_call.origin,
                destination=tool_call.destination,
                arguments=tool_call.arguments,
                decision=decision.decision.value,
                rule_id=decision.rule_id,
                reason=decision.reason,
                status=status.value,
                result=result_payload,
            )
            return ExecutionResponse(
                request_id=tool_call.request_id,
                decision=decision,
                executed=False,
                status=status,
                message=f"Action requires explicit approval under rule '{decision.rule_id}'.",
            )

        # 4. Decision is ALLOW: execute strictly on synthetic mock data
        status = ExecutionStatus.EXECUTED
        output: dict[str, Any]
        try:
            output = self._dispatch_sandbox_action(
                tool_name=tool_call.tool_name,
                args=tool_call.arguments,
                request_id=tool_call.request_id,
            )
            # Check for canary read in output
            if tool_call.tool_name == "read_file" and isinstance(output.get("content"), str):
                read_canaries = CanaryDetector.scan_content_for_canaries(output["content"])
                for canary in read_canaries:
                    self.db.insert_security_finding(
                        request_id=tool_call.request_id,
                        decision_id=decision.decision_id,
                        canary_token=canary.token_value,
                        canary_name=canary.name,
                        event_type="CANARY_READ",
                        severity=canary.severity,
                        evidence=f"Canary '{canary.name}' ({canary.token_value}) accessed via read_file at '{tool_call.arguments.get('path')}'.",
                        tool_name=tool_call.tool_name,
                        origin=tool_call.origin,
                        destination=tool_call.destination,
                    )
        except Exception as exc:
            output = {
                "executed": False,
                "error": str(exc),
                "error_type": type(exc).__name__,
            }

        self.db.insert_audit_record(
            request_id=tool_call.request_id,
            decision_id=decision.decision_id,
            tool_name=tool_call.tool_name,
            origin=tool_call.origin,
            destination=tool_call.destination,
            arguments=tool_call.arguments,
            decision=decision.decision.value,
            rule_id=decision.rule_id,
            reason=decision.reason,
            status=status.value,
            result=output,
        )

        return ExecutionResponse(
            request_id=tool_call.request_id,
            decision=decision,
            executed=True,
            status=status,
            output=output,
            message="Action authorized by policy gateway and executed on mock data.",
        )

    def resolve_approval(
        self,
        request_id: str,
        approver: str,
        approved: bool,
        reason: str = "",
    ) -> ExecutionResponse:
        """Resolve a pending approval request and record an approval event in audit history."""
        record = self.db.get_audit_record(request_id)
        if not record:
            raise ValueError(f"No audit record found for request_id: '{request_id}'")

        if record["status"] != ExecutionStatus.PENDING_APPROVAL.value:
            raise ValueError(
                f"Request '{request_id}' is not pending approval (current status: '{record['status']}')."
            )

        # Determine final status for the approval audit record
        target_status = (
            ExecutionStatus.APPROVED_EXECUTED.value
            if approved
            else ExecutionStatus.REJECTED.value
        )

        # Log authorization event into approval_events table
        self.db.insert_approval_event(
            request_id=request_id,
            decision_id=record["decision_id"],
            approver=approver,
            approved=approved,
            reason=reason,
            status_before=record["status"],
            status_after=target_status,
        )

        # Reconstruct tool call from the audit record for policy recheck
        tool_call = ToolCall(
            request_id=record["request_id"],
            tool_name=record["tool_name"],
            arguments=record["arguments"],
            origin=record["origin"],
            destination=record["destination"],
        )

        # Recheck policy before execution (Task 6 & Task 9)
        rechecked_decision = PolicyEngine.evaluate(tool_call)

        if not approved:
            status = ExecutionStatus.REJECTED
            rejection_result = {
                "executed": False,
                "approved": False,
                "approver": approver,
                "justification": reason,
            }
            self.db.update_audit_status(request_id, status.value, rejection_result)
            return ExecutionResponse(
                request_id=request_id,
                decision=rechecked_decision,
                executed=False,
                status=status,
                message=f"Action rejected by approver '{approver}'.",
            )

        # Invariant: BLOCKED actions must NEVER execute even if approved=True
        if rechecked_decision.decision == DecisionEnum.BLOCK:
            status = ExecutionStatus.BLOCKED
            block_result = {
                "executed": False,
                "approved": False,
                "approver": approver,
                "error": f"Policy recheck failed: Action '{record['tool_name']}' is BLOCKED by rule '{rechecked_decision.rule_id}': {rechecked_decision.reason}",
            }
            self.db.update_audit_status(request_id, status.value, block_result)
            raise ValueError(
                f"Policy recheck violation: tool call '{record['tool_name']}' is blocked by policy rule '{rechecked_decision.rule_id}' ({rechecked_decision.reason}). Cannot approve a blocked action."
            )

        # Authorized by administrator / approver and verified against policy
        status = ExecutionStatus.APPROVED_EXECUTED
        try:
            output = self._dispatch_sandbox_action(
                tool_name=record["tool_name"],
                args=record["arguments"],
                request_id=request_id,
            )
            output["approved_by"] = approver
            output["approval_reason"] = reason
        except Exception as exc:
            output = {
                "executed": False,
                "error": str(exc),
                "error_type": type(exc).__name__,
                "approved_by": approver,
            }

        self.db.update_audit_status(request_id, status.value, output)
        return ExecutionResponse(
            request_id=request_id,
            decision=rechecked_decision,
            executed=True,
            status=status,
            output=output,
            message=f"Action authorized by approver '{approver}', verified by policy gateway, and executed.",
        )

    def _dispatch_sandbox_action(
        self,
        tool_name: str,
        args: dict[str, Any],
        request_id: str,
    ) -> dict[str, Any]:
        """Dispatch an authorized action strictly to the isolated mock sandbox."""
        if tool_name == "read_file":
            return self.sandbox.read_file(path=args["path"])
        if tool_name == "write_file":
            return self.sandbox.write_file(path=args["path"], content=args["content"])
        if tool_name == "search_kb":
            return self.sandbox.search_kb(query=args["query"])
        if tool_name == "query_metrics":
            return self.sandbox.query_metrics(metric_name=args["metric_name"])
        if tool_name == "fetch_url":
            return self.sandbox.fetch_url(
                url=args["url"],
                request_id=request_id,
                method=args.get("method", "GET"),
                payload=args.get("payload"),
            )
        if tool_name == "send_email":
            return self.sandbox.send_email(
                to=args["to"],
                subject=args["subject"],
                body=args["body"],
                request_id=request_id,
            )
        if tool_name == "execute_command":
            return self.sandbox.execute_command(command=args["command"])
        if tool_name == "database_migration":
            return self.sandbox.database_migration(migration_id=args["migration_id"])
        if tool_name == "restart_service":
            return self.sandbox.restart_service(service_name=args["service_name"])

        raise ValueError(f"Unknown sandbox tool dispatch: '{tool_name}'")


# Global execution service
execution_service = ExecutionService()
