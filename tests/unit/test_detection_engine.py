"""Tests for the detection engine and built-in rules."""

from src.detection.engine import DetectionEngine
from src.detection.rules import (
    detect_unauthorized_api_calls,
    detect_root_account_usage,
    detect_iam_privilege_escalation,
    detect_cloudtrail_tampering,
    detect_guardduty_high_severity,
    detect_brute_force_pattern,
    detect_mfa_deactivation,
)
from src.shared.models import SecurityEvent, Severity, EventSource


class TestDetectionEngine:
    def test_evaluates_all_rules(self, security_event):
        engine = DetectionEngine()
        results = engine.evaluate(security_event)
        # Should return results (some matched, some not)
        assert isinstance(results, list)

    def test_catches_rule_exceptions(self):
        """Engine should not crash if a rule raises."""
        event = SecurityEvent(
            source="test", event_type="Test", source_ip="0.0.0.0"
        )
        engine = DetectionEngine()
        # Should complete without raising
        results = engine.evaluate(event)
        assert isinstance(results, list)


class TestUnauthorizedApiCallsRule:
    def test_matches_access_denied(self):
        event = SecurityEvent(
            source="cloudtrail",
            event_type="GetObject",
            source_ip="198.51.100.1",
            user_identity="arn:aws:iam::123456789012:user/test",
            raw_event={"errorCode": "AccessDenied"},
        )
        result = detect_unauthorized_api_calls(event)
        assert result is not None
        assert result.matched is True
        assert result.rule_id == "HOLO-001"

    def test_ignores_successful_calls(self):
        event = SecurityEvent(
            source="cloudtrail",
            event_type="GetObject",
            source_ip="10.0.0.1",
            raw_event={"errorCode": ""},
        )
        result = detect_unauthorized_api_calls(event)
        assert result is None


class TestRootAccountRule:
    def test_matches_root_activity(self, root_login_event):
        from src.ingestion.parsers import parse_event

        event = parse_event(root_login_event)
        result = detect_root_account_usage(event)
        assert result is not None
        assert result.severity == Severity.CRITICAL.value
        assert result.rule_id == "HOLO-002"

    def test_ignores_iam_user(self, security_event):
        result = detect_root_account_usage(security_event)
        assert result is None


class TestPrivilegeEscalationRule:
    def test_matches_escalation_action(self):
        event = SecurityEvent(
            source="cloudtrail",
            event_type="AttachRolePolicy",
            source_ip="198.51.100.1",
            user_identity="arn:aws:iam::123456789012:user/suspicious",
        )
        result = detect_iam_privilege_escalation(event)
        assert result is not None
        assert result.severity == Severity.HIGH.value
        assert "revoke_credentials" in result.recommended_actions

    def test_ignores_normal_action(self):
        event = SecurityEvent(
            source="cloudtrail",
            event_type="DescribeInstances",
            source_ip="10.0.0.1",
        )
        result = detect_iam_privilege_escalation(event)
        assert result is None


class TestCloudTrailTamperingRule:
    def test_matches_stop_logging(self):
        event = SecurityEvent(
            source="cloudtrail",
            event_type="StopLogging",
            source_ip="198.51.100.1",
            user_identity="arn:aws:iam::123456789012:user/rogue-admin",
        )
        result = detect_cloudtrail_tampering(event)
        assert result is not None
        assert result.severity == Severity.CRITICAL.value


class TestGuardDutyRule:
    def test_matches_high_severity_finding(self):
        event = SecurityEvent(
            source="guardduty",
            event_type="UnauthorizedAccess:EC2/MaliciousIPCaller",
            source_ip="203.0.113.50",
            raw_event={"detail": {"severity": 8.0}},
        )
        result = detect_guardduty_high_severity(event)
        assert result is not None
        assert result.matched is True

    def test_ignores_low_severity(self):
        event = SecurityEvent(
            source="guardduty",
            event_type="Recon:EC2/PortProbeUnprotectedPort",
            source_ip="203.0.113.50",
            raw_event={"detail": {"severity": 3.0}},
        )
        result = detect_guardduty_high_severity(event)
        assert result is None

    def test_ignores_non_guardduty(self):
        event = SecurityEvent(
            source="cloudtrail",
            event_type="GetObject",
            source_ip="10.0.0.1",
            raw_event={"detail": {"severity": 9.0}},
        )
        result = detect_guardduty_high_severity(event)
        assert result is None


class TestBruteForceRule:
    def test_matches_failed_login(self):
        event = SecurityEvent(
            source="cloudtrail",
            event_type="ConsoleLogin",
            source_ip="198.51.100.1",
            user_identity="arn:aws:iam::123456789012:user/target",
            raw_event={"responseElements": {"ConsoleLogin": "Failure"}},
        )
        result = detect_brute_force_pattern(event)
        assert result is not None
        assert result.severity == Severity.HIGH.value

    def test_ignores_successful_login(self):
        event = SecurityEvent(
            source="cloudtrail",
            event_type="ConsoleLogin",
            source_ip="10.0.0.1",
            raw_event={"responseElements": {"ConsoleLogin": "Success"}},
        )
        result = detect_brute_force_pattern(event)
        assert result is None


class TestMfaDeactivationRule:
    def test_matches_mfa_deactivation(self):
        event = SecurityEvent(
            source="cloudtrail",
            event_type="DeactivateMFADevice",
            source_ip="198.51.100.1",
            user_identity="arn:aws:iam::123456789012:user/compromised",
        )
        result = detect_mfa_deactivation(event)
        assert result is not None
        assert result.severity == Severity.CRITICAL.value
        assert "disable_user" in result.recommended_actions
