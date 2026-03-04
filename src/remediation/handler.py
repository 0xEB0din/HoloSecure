"""Remediation handler — orchestrates automated response actions.

Every remediation request passes through the guardrails module before
execution. Actions can be blocked by severity threshold, dry-run mode,
or explicit deny-list rules.

Flow:
  1. Parse remediation request from detection engine
  2. Evaluate guardrails (severity gate, dry-run, deny-list)
  3. Execute approved actions via the actions module
  4. Log results and publish audit trail to SNS
"""

import json
import os

from src.shared.logger import get_logger
from src.shared.models import SecurityEvent, RemediationRequest, RemediationAction
from src.shared import aws_clients
from src.remediation.guardrails import evaluate_guardrails
from src.remediation.actions import execute_action

logger = get_logger(__name__)

ALERT_TOPIC = os.environ.get("ALERT_TOPIC", "")
DRY_RUN = os.environ.get("DRY_RUN", "true").lower() == "true"


def lambda_handler(event: dict, context) -> dict:
    security_event = SecurityEvent(**event["event"])
    actions = event.get("actions", [])
    rule_id = event.get("rule_id", "unknown")

    results = []

    for action_name in actions:
        request = RemediationRequest(
            event=security_event,
            action=action_name,
            dry_run=DRY_RUN,
        )

        # Guardrail check
        approved, reason = evaluate_guardrails(request)
        request.approved = approved

        if not approved:
            logger.info(
                f"Remediation blocked: {action_name} for event "
                f"{security_event.event_id} — {reason}"
            )
            request.result = f"BLOCKED: {reason}"
            results.append(request.to_dict())
            continue

        # Execute
        try:
            outcome = execute_action(request)
            request.result = outcome
            logger.info(
                f"Remediation executed: {action_name} for "
                f"{security_event.event_id} — {outcome}"
            )
        except Exception as exc:
            request.result = f"ERROR: {str(exc)}"
            logger.exception(f"Remediation failed: {action_name}")

        results.append(request.to_dict())

    _publish_audit_trail(security_event, rule_id, results)

    return {
        "event_id": security_event.event_id,
        "actions_requested": len(actions),
        "actions_executed": sum(1 for r in results if "BLOCKED" not in (r.get("result") or "")),
    }


def _publish_audit_trail(event: SecurityEvent, rule_id: str, results: list) -> None:
    if not ALERT_TOPIC:
        return

    message = {
        "type": "remediation_audit",
        "event_id": event.event_id,
        "rule_id": rule_id,
        "source_ip": event.source_ip,
        "results": [
            {"action": r["action"], "approved": r["approved"], "result": r.get("result")}
            for r in results
        ],
    }

    aws_clients.sns().publish(
        TopicArn=ALERT_TOPIC,
        Subject=f"[HoloSecure] Remediation audit — {event.event_id[:8]}",
        Message=json.dumps(message, indent=2),
    )
