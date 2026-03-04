"""Tests for the event parser module."""

from src.ingestion.parsers import parse_event, _detect_source
from src.shared.models import EventSource, Severity


class TestSourceDetection:
    def test_detects_cloudtrail(self, cloudtrail_event):
        assert _detect_source(cloudtrail_event) == EventSource.CLOUDTRAIL.value

    def test_detects_guardduty(self, guardduty_event):
        assert _detect_source(guardduty_event) == EventSource.GUARDDUTY.value

    def test_detects_vpc_flow(self):
        raw = {"version": 2, "interface-id": "eni-abc123", "srcaddr": "10.0.0.1"}
        assert _detect_source(raw) == EventSource.VPC_FLOW.value

    def test_detects_waf(self):
        raw = {"source": "aws.waf", "detail": {"action": "BLOCK"}}
        assert _detect_source(raw) == EventSource.WAF.value

    def test_falls_back_to_custom(self):
        raw = {"foo": "bar"}
        assert _detect_source(raw) == EventSource.CUSTOM.value


class TestCloudTrailParser:
    def test_parses_basic_fields(self, cloudtrail_event):
        event = parse_event(cloudtrail_event)
        assert event.source == EventSource.CLOUDTRAIL.value
        assert event.event_type == "CreateAccessKey"
        assert event.source_ip == "198.51.100.42"
        assert event.account_id == "123456789012"
        assert event.region == "us-east-1"

    def test_classifies_high_risk_action(self, cloudtrail_event):
        event = parse_event(cloudtrail_event)
        assert event.severity == Severity.HIGH.value

    def test_extracts_user_identity(self, cloudtrail_event):
        event = parse_event(cloudtrail_event)
        assert "attacker" in event.user_identity

    def test_low_severity_for_benign_action(self):
        raw = {
            "eventVersion": "1.08",
            "eventSource": "ec2.amazonaws.com",
            "eventName": "DescribeInstances",
            "sourceIPAddress": "10.0.0.1",
            "awsRegion": "us-east-1",
        }
        event = parse_event(raw)
        assert event.severity == Severity.LOW.value


class TestGuardDutyParser:
    def test_parses_basic_fields(self, guardduty_event):
        event = parse_event(guardduty_event)
        assert event.source == EventSource.GUARDDUTY.value
        assert event.source_ip == "203.0.113.50"
        assert event.account_id == "123456789012"

    def test_maps_severity_from_score(self, guardduty_event):
        event = parse_event(guardduty_event)
        assert event.severity == Severity.HIGH.value

    def test_critical_severity_for_high_score(self, guardduty_event):
        guardduty_event["detail"]["severity"] = 9.5
        event = parse_event(guardduty_event)
        assert event.severity == Severity.CRITICAL.value


class TestGenericParser:
    def test_handles_minimal_payload(self):
        raw = {"source": "custom-app", "event_type": "login_failed", "source_ip": "10.0.0.5"}
        event = parse_event(raw)
        assert event.source == "custom-app"
        assert event.event_type == "login_failed"
        assert event.source_ip == "10.0.0.5"
