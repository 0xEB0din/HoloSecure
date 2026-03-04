"""Enrichment handler — augments security events with additional context.

Pulls in:
  - AWS resource metadata  (EC2 instance tags, IAM user details)
  - GuardDuty correlations (related findings for the same resource)
  - GeoIP approximation    (from GuardDuty remote IP details)

The enriched event is written back to DynamoDB so downstream consumers
(dashboards, SIEM exports, analysts) always see the full picture.
"""

import os

from src.shared.logger import get_logger
from src.shared.models import SecurityEvent
from src.shared import aws_clients

logger = get_logger(__name__)

EVENT_TABLE = os.environ.get("EVENT_TABLE", "holosecure-events-dev")


def lambda_handler(event: dict, context) -> dict:
    security_event = SecurityEvent(**event)
    enrichment = {}

    enrichment.update(_enrich_aws_context(security_event))
    enrichment.update(_enrich_guardduty(security_event))
    enrichment.update(_correlate_recent_activity(security_event))

    security_event.enrichment = enrichment
    _update_event(security_event)

    logger.info(f"Enriched event {security_event.event_id} with {len(enrichment)} fields")
    return {"event_id": security_event.event_id, "enrichment_keys": list(enrichment.keys())}


def _enrich_aws_context(event: SecurityEvent) -> dict:
    """Pull resource metadata from EC2 / IAM."""
    context = {}

    if event.resource_arn and event.resource_arn.startswith("i-"):
        try:
            resp = aws_clients.ec2().describe_instances(InstanceIds=[event.resource_arn])
            reservations = resp.get("Reservations", [])
            if reservations:
                instance = reservations[0]["Instances"][0]
                context["instance_type"] = instance.get("InstanceType", "")
                context["instance_state"] = instance["State"]["Name"]
                context["vpc_id"] = instance.get("VpcId", "")
                context["tags"] = {
                    t["Key"]: t["Value"]
                    for t in instance.get("Tags", [])
                }
        except Exception:
            logger.debug(f"Could not fetch EC2 metadata for {event.resource_arn}")

    if event.user_identity and not event.user_identity.startswith("arn:aws:sts"):
        try:
            username = event.user_identity.split("/")[-1]
            resp = aws_clients.iam().get_user(UserName=username)
            user = resp.get("User", {})
            context["iam_user_created"] = str(user.get("CreateDate", ""))
            context["iam_user_arn"] = user.get("Arn", "")
        except Exception:
            logger.debug(f"Could not fetch IAM metadata for {event.user_identity}")

    return context


def _enrich_guardduty(event: SecurityEvent) -> dict:
    """Pull related GuardDuty findings for the source IP."""
    context = {}
    if not event.source_ip or event.source_ip == "0.0.0.0":
        return context

    try:
        gd = aws_clients.guardduty()
        detectors = gd.list_detectors().get("DetectorIds", [])
        if not detectors:
            return context

        detector_id = detectors[0]
        criterion = {
            "service.action.networkConnectionAction.remoteIpDetails.ipAddressV4": {
                "Eq": [event.source_ip]
            }
        }
        resp = gd.list_findings(
            DetectorId=detector_id,
            FindingCriteria={"Criterion": criterion},
            MaxResults=5,
        )
        finding_ids = resp.get("FindingIds", [])
        if finding_ids:
            context["related_guardduty_findings"] = finding_ids
            context["guardduty_finding_count"] = len(finding_ids)
    except Exception:
        logger.debug(f"GuardDuty enrichment skipped for {event.source_ip}")

    return context


def _correlate_recent_activity(event: SecurityEvent) -> dict:
    """Check DynamoDB for recent events from the same source IP."""
    context = {}
    if not event.source_ip or event.source_ip == "0.0.0.0":
        return context

    try:
        table = aws_clients.dynamodb_resource().Table(EVENT_TABLE)
        resp = table.query(
            IndexName="source-ip-index",
            KeyConditionExpression="source_ip = :ip",
            ExpressionAttributeValues={":ip": event.source_ip},
            Limit=20,
            ScanIndexForward=False,
        )
        items = resp.get("Items", [])
        context["recent_events_from_ip"] = len(items)
        if items:
            context["first_seen"] = items[-1].get("timestamp", "")
            context["last_seen"] = items[0].get("timestamp", "")
    except Exception:
        logger.debug(f"Correlation query failed for {event.source_ip}")

    return context


def _update_event(event: SecurityEvent) -> None:
    table = aws_clients.dynamodb_resource().Table(EVENT_TABLE)
    table.update_item(
        Key={"event_id": event.event_id, "timestamp": event.timestamp},
        UpdateExpression="SET enrichment = :e",
        ExpressionAttributeValues={":e": event.enrichment},
    )
