"""Shared pytest fixtures for the HoloSecure test suite."""

import os
import pytest

# Force test-safe environment variables before any module imports boto3
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")
os.environ.setdefault("AWS_SECURITY_TOKEN", "testing")
os.environ.setdefault("ENVIRONMENT", "test")
os.environ.setdefault("EVENT_TABLE", "holosecure-events-test")
os.environ.setdefault("ALERT_TOPIC", "arn:aws:sns:us-east-1:123456789012:test-alerts")
os.environ.setdefault("DRY_RUN", "true")
os.environ.setdefault("LOG_LEVEL", "DEBUG")

from src.shared.models import SecurityEvent, Severity, EventSource  # noqa: E402


@pytest.fixture
def cloudtrail_event():
    """A realistic CloudTrail event payload."""
    return {
        "eventVersion": "1.08",
        "eventSource": "iam.amazonaws.com",
        "eventName": "CreateAccessKey",
        "awsRegion": "us-east-1",
        "sourceIPAddress": "198.51.100.42",
        "userIdentity": {
            "type": "IAMUser",
            "arn": "arn:aws:iam::123456789012:user/attacker",
            "userName": "attacker",
        },
        "recipientAccountId": "123456789012",
        "requestParameters": {"userName": "victim-user"},
        "responseElements": {"accessKey": {"accessKeyId": "AKIAIOSFODNN7EXAMPLE"}},
        "errorCode": "",
    }


@pytest.fixture
def guardduty_event():
    """A realistic GuardDuty finding event."""
    return {
        "source": "aws.guardduty",
        "detail-type": "GuardDuty Finding",
        "detail": {
            "type": "UnauthorizedAccess:EC2/MaliciousIPCaller.Custom",
            "severity": 8.5,
            "accountId": "123456789012",
            "region": "us-east-1",
            "updatedAt": "2025-01-15T10:30:00Z",
            "resource": {
                "instanceDetails": {"instanceId": "i-0abc123def456789"}
            },
            "service": {
                "action": {
                    "networkConnectionAction": {
                        "remoteIpDetails": {"ipAddressV4": "203.0.113.50"}
                    }
                }
            },
        },
    }


@pytest.fixture
def security_event():
    """A pre-parsed SecurityEvent for unit tests."""
    return SecurityEvent(
        source=EventSource.CLOUDTRAIL.value,
        event_type="CreateAccessKey",
        source_ip="198.51.100.42",
        severity=Severity.HIGH.value,
        account_id="123456789012",
        region="us-east-1",
        user_identity="arn:aws:iam::123456789012:user/attacker",
        raw_event={
            "eventName": "CreateAccessKey",
            "userIdentity": {"type": "IAMUser", "arn": "arn:aws:iam::123456789012:user/attacker"},
        },
    )


@pytest.fixture
def root_login_event():
    """A CloudTrail event showing root account console login."""
    return {
        "eventVersion": "1.08",
        "eventSource": "signin.amazonaws.com",
        "eventName": "ConsoleLogin",
        "awsRegion": "us-east-1",
        "sourceIPAddress": "198.51.100.99",
        "userIdentity": {
            "type": "Root",
            "arn": "arn:aws:iam::123456789012:root",
        },
        "recipientAccountId": "123456789012",
        "responseElements": {"ConsoleLogin": "Success"},
    }
