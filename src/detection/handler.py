"""Detection handler — evaluates security events against the rule engine
and triggers downstream enrichment / remediation when a rule matches.
"""

import json
import os

from src.shared.logger import get_logger
from src.shared.models import SecurityEvent, Severity
from src.shared import aws_clients
from src.detection.engine import DetectionEngine

logger = get_logger(__name__)

ENRICHMENT_FUNCTION = os.environ.get("ENRICHMENT_FUNCTION", "")
REMEDIATION_FUNCTION = os.environ.get("REMEDIATION_FUNCTION", "")
ALERT_TOPIC = os.environ.get("ALERT_TOPIC", "")

_engine = DetectionEngine()


def lambda_handler(event: dict, context) -> dict:
    """Evaluate a single security event against all loaded rules."""
    security_event = SecurityEvent(**event)
    results = _engine.evaluate(security_event)

    matches = [r for r in results if r.matched]
    if not matches:
        return {"matched": False, "rules_evaluated": len(results)}

    logger.info(
        f"Event {security_event.event_id} triggered {len(matches)} detection(s)"
    )

    # Promote severity to the highest match
    max_severity = max(
        matches,
        key=lambda r: list(Severity).index(Severity(r.severity)),
    )
    security_event.severity = max_severity.severity
    security_event.detection_matches = [m.to_dict() for m in matches]

    _invoke_enrichment(security_event)
    _handle_remediation(security_event, matches)
    _publish_alert(security_event, matches)

    return {
        "matched": True,
        "rules_evaluated": len(results),
        "matches": len(matches),
        "severity": security_event.severity,
    }


def _invoke_enrichment(event: SecurityEvent) -> None:
    if not ENRICHMENT_FUNCTION:
        return
    aws_clients.lambda_client().invoke(
        FunctionName=ENRICHMENT_FUNCTION,
        InvocationType="Event",
        Payload=json.dumps(event.to_dict()),
    )


def _handle_remediation(event: SecurityEvent, matches: list) -> None:
    if not REMEDIATION_FUNCTION:
        return

    for match in matches:
        if not match.recommended_actions:
            continue

        payload = {
            "event": event.to_dict(),
            "actions": match.recommended_actions,
            "rule_id": match.rule_id,
            "severity": match.severity,
        }
        aws_clients.lambda_client().invoke(
            FunctionName=REMEDIATION_FUNCTION,
            InvocationType="Event",
            Payload=json.dumps(payload),
        )


def _publish_alert(event: SecurityEvent, matches: list) -> None:
    if not ALERT_TOPIC:
        return

    subject = f"[HoloSecure][{event.severity}] {event.event_type} from {event.source_ip}"
    # SNS subject max 100 chars
    subject = subject[:100]

    rule_names = ", ".join(m.rule_name for m in matches)
    message = (
        f"Security event detected\n"
        f"{'=' * 40}\n"
        f"Event ID:   {event.event_id}\n"
        f"Source:     {event.source}\n"
        f"Type:       {event.event_type}\n"
        f"Source IP:  {event.source_ip}\n"
        f"Severity:   {event.severity}\n"
        f"Account:    {event.account_id}\n"
        f"Region:     {event.region}\n"
        f"Rules:      {rule_names}\n"
        f"Timestamp:  {event.timestamp}\n"
    )

    aws_clients.sns().publish(
        TopicArn=ALERT_TOPIC,
        Subject=subject,
        Message=message,
    )
