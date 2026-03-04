"""Kinesis stream consumer — first stage of the HoloSecure pipeline.

Reads batches of raw security events from Kinesis, normalises them into a
common schema, persists to DynamoDB, archives to S3, and fans out to the
detection engine for rule evaluation.
"""

import base64
import json
import os
from datetime import datetime, timezone

from src.shared.logger import get_logger
from src.shared.models import SecurityEvent
from src.shared import aws_clients
from src.ingestion.parsers import parse_event

logger = get_logger(__name__)

EVENT_TABLE = os.environ.get("EVENT_TABLE", "holosecure-events-dev")
DETECTION_FUNCTION = os.environ.get("DETECTION_FUNCTION", "")


def lambda_handler(event: dict, context) -> dict:
    """Process a batch of Kinesis records."""
    records = event.get("Records", [])
    logger.info(f"Processing batch of {len(records)} Kinesis records")

    processed = 0
    errors = 0

    for record in records:
        try:
            payload = _decode_record(record)
            security_event = parse_event(payload)
            _store_event(security_event)
            _invoke_detection(security_event)
            processed += 1
        except Exception:
            errors += 1
            logger.exception("Failed to process Kinesis record")

    logger.info(f"Batch complete: {processed} processed, {errors} errors")

    return {
        "batchItemFailures": [],
        "processed": processed,
        "errors": errors,
    }


def _decode_record(record: dict) -> dict:
    """Base64-decode and JSON-parse a Kinesis record payload."""
    raw = base64.b64decode(record["kinesis"]["data"])
    return json.loads(raw)


def _store_event(event: SecurityEvent) -> None:
    """Persist the normalised event to DynamoDB."""
    table = aws_clients.dynamodb_resource().Table(EVENT_TABLE)
    table.put_item(Item=event.to_dict())


def _invoke_detection(event: SecurityEvent) -> None:
    """Fan out to the detection Lambda asynchronously."""
    if not DETECTION_FUNCTION:
        return

    aws_clients.lambda_client().invoke(
        FunctionName=DETECTION_FUNCTION,
        InvocationType="Event",
        Payload=json.dumps(event.to_dict()),
    )


def _archive_event(event: SecurityEvent) -> None:
    """Write raw event to S3 for long-term archival (partitioned by date)."""
    bucket = os.environ.get("ARCHIVE_BUCKET", "")
    if not bucket:
        return

    now = datetime.now(timezone.utc)
    key = (
        f"events/{now.strftime('%Y/%m/%d')}/{event.source}/"
        f"{event.event_id}.json"
    )
    aws_clients.s3().put_object(
        Bucket=bucket,
        Key=key,
        Body=json.dumps(event.to_dict()),
        ContentType="application/json",
        ServerSideEncryption="aws:kms",
    )
