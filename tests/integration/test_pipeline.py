"""Integration tests — exercise the full ingest → detect → remediate pipeline.

Uses moto to mock AWS services so the entire flow can run without
real infrastructure.
"""

import base64
import json

import pytest
from moto import mock_aws

import boto3

from src.shared.models import Severity


@mock_aws
class TestIngestionPipeline:
    """Verify the ingestion handler processes Kinesis records end-to-end."""

    def _setup_dynamodb(self):
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        ddb.create_table(
            TableName="holosecure-events-test",
            KeySchema=[
                {"AttributeName": "event_id", "KeyType": "HASH"},
                {"AttributeName": "timestamp", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "event_id", "AttributeType": "S"},
                {"AttributeName": "timestamp", "AttributeType": "S"},
            ],
            BillingMode="PAY_PER_REQUEST",
        )
        return ddb

    def _make_kinesis_record(self, payload: dict) -> dict:
        encoded = base64.b64encode(json.dumps(payload).encode()).decode()
        return {
            "kinesis": {
                "data": encoded,
                "sequenceNumber": "1",
                "partitionKey": "test",
            },
            "eventSource": "aws:kinesis",
        }

    def test_processes_cloudtrail_event(self, cloudtrail_event):
        self._setup_dynamodb()

        from src.ingestion.handler import lambda_handler

        kinesis_event = {"Records": [self._make_kinesis_record(cloudtrail_event)]}
        result = lambda_handler(kinesis_event, None)

        assert result["processed"] == 1
        assert result["errors"] == 0

    def test_processes_batch_of_events(self, cloudtrail_event, guardduty_event):
        self._setup_dynamodb()

        from src.ingestion.handler import lambda_handler

        kinesis_event = {
            "Records": [
                self._make_kinesis_record(cloudtrail_event),
                self._make_kinesis_record(guardduty_event),
            ]
        }
        result = lambda_handler(kinesis_event, None)

        assert result["processed"] == 2
        assert result["errors"] == 0

    def test_handles_malformed_record_gracefully(self):
        self._setup_dynamodb()

        from src.ingestion.handler import lambda_handler

        bad_record = {
            "kinesis": {
                "data": base64.b64encode(b"not json").decode(),
                "sequenceNumber": "1",
                "partitionKey": "test",
            }
        }
        result = lambda_handler({"Records": [bad_record]}, None)

        assert result["errors"] == 1
        assert result["processed"] == 0


@mock_aws
class TestDetectionPipeline:
    """Verify detection rules fire correctly for known-bad events."""

    def test_detects_privilege_escalation(self):
        from src.detection.engine import DetectionEngine
        from src.shared.models import SecurityEvent

        event = SecurityEvent(
            source="cloudtrail",
            event_type="AttachRolePolicy",
            source_ip="198.51.100.1",
            user_identity="arn:aws:iam::123456789012:user/attacker",
            raw_event={"eventName": "AttachRolePolicy"},
        )

        engine = DetectionEngine()
        results = engine.evaluate(event)
        matches = [r for r in results if r.matched]

        assert len(matches) >= 1
        rule_ids = [m.rule_id for m in matches]
        assert "HOLO-003" in rule_ids

    def test_no_false_positives_for_read_only(self):
        from src.detection.engine import DetectionEngine
        from src.shared.models import SecurityEvent

        event = SecurityEvent(
            source="cloudtrail",
            event_type="DescribeInstances",
            source_ip="10.0.0.1",
            raw_event={"eventName": "DescribeInstances", "errorCode": ""},
        )

        engine = DetectionEngine()
        results = engine.evaluate(event)
        matches = [r for r in results if r.matched]

        assert len(matches) == 0
