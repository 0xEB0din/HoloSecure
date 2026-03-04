"""Alerting handler — formats and dispatches security notifications.

Supports SNS delivery with structured JSON payloads. The handler also
pushes findings to Security Hub in ASFF format so they surface in the
AWS-native security console alongside GuardDuty and Inspector findings.
"""

import json
import os
from datetime import datetime, timezone

from src.shared.logger import get_logger
from src.shared.models import SecurityEvent, Severity
from src.shared import aws_clients

logger = get_logger(__name__)

ALERT_TOPIC = os.environ.get("ALERT_TOPIC", "")
ACCOUNT_ID = os.environ.get("ACCOUNT_ID", "")
REGION = os.environ.get("AWS_REGION", "us-east-1")


def lambda_handler(event: dict, context) -> dict:
    security_event = SecurityEvent(**event)

    _send_sns_alert(security_event)

    if Severity(security_event.severity) in (Severity.HIGH, Severity.CRITICAL):
        _send_to_security_hub(security_event)

    return {"event_id": security_event.event_id, "alerted": True}


def _send_sns_alert(event: SecurityEvent) -> None:
    if not ALERT_TOPIC:
        return

    severity_tag = f"[{event.severity}]"
    subject = f"HoloSecure {severity_tag} {event.event_type}"[:100]

    payload = {
        "source": "holosecure",
        "event_id": event.event_id,
        "severity": event.severity,
        "event_type": event.event_type,
        "source_ip": event.source_ip,
        "account_id": event.account_id,
        "region": event.region,
        "user_identity": event.user_identity,
        "timestamp": event.timestamp,
        "detection_matches": event.detection_matches,
        "enrichment": event.enrichment,
    }

    aws_clients.sns().publish(
        TopicArn=ALERT_TOPIC,
        Subject=subject,
        Message=json.dumps(payload, indent=2),
    )


def _send_to_security_hub(event: SecurityEvent) -> None:
    """Push the finding to AWS Security Hub in ASFF format."""
    if not ACCOUNT_ID:
        logger.debug("ACCOUNT_ID not set — skipping Security Hub export")
        return

    now = datetime.now(timezone.utc).isoformat()
    severity_map = {
        Severity.LOW.value: 20,
        Severity.MEDIUM.value: 50,
        Severity.HIGH.value: 70,
        Severity.CRITICAL.value: 90,
    }

    finding = {
        "SchemaVersion": "2018-10-08",
        "Id": event.event_id,
        "ProductArn": f"arn:aws:securityhub:{REGION}:{ACCOUNT_ID}:product/{ACCOUNT_ID}/default",
        "GeneratorId": "holosecure-detection-engine",
        "AwsAccountId": event.account_id or ACCOUNT_ID,
        "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
        "CreatedAt": event.timestamp or now,
        "UpdatedAt": now,
        "Severity": {
            "Normalized": severity_map.get(event.severity, 50),
        },
        "Title": f"HoloSecure: {event.event_type}",
        "Description": (
            f"Security event {event.event_type} from {event.source_ip} "
            f"detected by HoloSecure. Source: {event.source}."
        ),
        "Resources": [
            {
                "Type": "Other",
                "Id": event.resource_arn or event.source_ip,
                "Region": event.region or REGION,
            }
        ],
        "Network": {
            "SourceIpV4": event.source_ip,
            "Direction": "IN",
        },
    }

    try:
        aws_clients.securityhub().batch_import_findings(Findings=[finding])
        logger.info(f"Finding {event.event_id} pushed to Security Hub")
    except Exception:
        logger.exception("Failed to push finding to Security Hub")
