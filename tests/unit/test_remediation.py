"""Tests for the remediation guardrails and action dispatch."""

import os
from unittest.mock import patch

from src.shared.models import SecurityEvent, RemediationRequest, Severity, RemediationAction
from src.remediation.guardrails import evaluate_guardrails
from src.remediation.actions import execute_action


class TestGuardrails:
    def _make_request(self, severity="HIGH", dry_run=False, source_ip="198.51.100.1"):
        event = SecurityEvent(
            source="cloudtrail",
            event_type="CreateAccessKey",
            source_ip=source_ip,
            severity=severity,
            user_identity="arn:aws:iam::123456789012:user/test",
        )
        return RemediationRequest(
            event=event,
            action=RemediationAction.BLOCK_IP.value,
            dry_run=dry_run,
        )

    def test_blocks_on_dry_run(self):
        request = self._make_request(dry_run=True)
        approved, reason = evaluate_guardrails(request)
        assert not approved
        assert "dry-run" in reason

    def test_approves_high_severity_when_not_dry_run(self):
        with patch.dict(os.environ, {"REQUIRE_APPROVAL_ABOVE": "MEDIUM"}):
            # Need to reimport to pick up env change
            from src.remediation import guardrails
            request = self._make_request(severity="HIGH", dry_run=False)
            approved, reason = guardrails.evaluate_guardrails(request)
            assert approved

    def test_blocks_low_severity(self):
        request = self._make_request(severity="LOW", dry_run=False)
        approved, reason = evaluate_guardrails(request)
        assert not approved
        assert "severity" in reason.lower() or "threshold" in reason.lower()

    def test_blocks_allowlisted_ip(self):
        with patch.dict(os.environ, {"IP_ALLOWLIST": "198.51.100.1,10.0.0.1"}):
            from src.remediation import guardrails

            # Force reload of module-level sets
            guardrails._IP_ALLOWLIST = set(
                os.environ.get("IP_ALLOWLIST", "").split(",")
            ) - {""}

            request = self._make_request(
                severity="HIGH", dry_run=False, source_ip="198.51.100.1"
            )
            approved, reason = guardrails.evaluate_guardrails(request)
            assert not approved
            assert "allowlist" in reason

            # Cleanup
            guardrails._IP_ALLOWLIST = set()


class TestActionDispatch:
    def test_unknown_action_returns_error(self):
        event = SecurityEvent(
            source="test", event_type="Test", source_ip="10.0.0.1"
        )
        request = RemediationRequest(
            event=event, action="nonexistent_action", dry_run=True
        )
        result = execute_action(request)
        assert "UNKNOWN_ACTION" in result

    def test_block_ip_dry_run(self):
        event = SecurityEvent(
            source="test",
            event_type="Test",
            source_ip="198.51.100.42",
        )
        request = RemediationRequest(
            event=event,
            action=RemediationAction.BLOCK_IP.value,
            dry_run=True,
        )
        result = execute_action(request)
        assert "DRY_RUN" in result
        assert "198.51.100.42" in result

    def test_revoke_credentials_dry_run(self):
        event = SecurityEvent(
            source="test",
            event_type="Test",
            source_ip="10.0.0.1",
            user_identity="arn:aws:iam::123456789012:user/testuser",
        )
        request = RemediationRequest(
            event=event,
            action=RemediationAction.REVOKE_CREDENTIALS.value,
            dry_run=True,
        )
        result = execute_action(request)
        assert "DRY_RUN" in result
        assert "testuser" in result

    def test_block_ip_skips_invalid_ip(self):
        event = SecurityEvent(
            source="test", event_type="Test", source_ip="0.0.0.0"
        )
        request = RemediationRequest(
            event=event,
            action=RemediationAction.BLOCK_IP.value,
            dry_run=False,
        )
        result = execute_action(request)
        assert "SKIPPED" in result

    def test_disable_user_dry_run(self):
        event = SecurityEvent(
            source="test",
            event_type="Test",
            source_ip="10.0.0.1",
            user_identity="arn:aws:iam::123456789012:user/rogue",
        )
        request = RemediationRequest(
            event=event,
            action=RemediationAction.DISABLE_USER.value,
            dry_run=True,
        )
        result = execute_action(request)
        assert "DRY_RUN" in result
        assert "rogue" in result
