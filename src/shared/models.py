"""Domain models for the HoloSecure pipeline.

Kept deliberately simple — plain dataclasses rather than a heavyweight ORM —
so they serialise cleanly across Lambda invocations.
"""

from __future__ import annotations

import uuid
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from decimal import Decimal
from enum import Enum
from typing import Optional


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @classmethod
    def from_score(cls, score: float) -> "Severity":
        if score >= 9.0:
            return cls.CRITICAL
        if score >= 7.0:
            return cls.HIGH
        if score >= 4.0:
            return cls.MEDIUM
        return cls.LOW


class EventSource(str, Enum):
    CLOUDTRAIL = "cloudtrail"
    VPC_FLOW = "vpc_flow"
    GUARDDUTY = "guardduty"
    WAF = "waf"
    CUSTOM = "custom"


class RemediationAction(str, Enum):
    BLOCK_IP = "block_ip"
    REVOKE_CREDENTIALS = "revoke_credentials"
    ISOLATE_INSTANCE = "isolate_instance"
    DISABLE_USER = "disable_user"
    QUARANTINE_ROLE = "quarantine_role"


def _sanitize_for_dynamo(value):
    """Convert floats to Decimal (required by DynamoDB) recursively."""
    if isinstance(value, float):
        return Decimal(str(value))
    if isinstance(value, dict):
        return {k: _sanitize_for_dynamo(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_sanitize_for_dynamo(i) for i in value]
    return value


@dataclass
class SecurityEvent:
    source: str
    event_type: str
    source_ip: str
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    severity: str = Severity.LOW.value
    account_id: str = ""
    region: str = ""
    resource_arn: str = ""
    user_identity: str = ""
    raw_event: dict = field(default_factory=dict)
    enrichment: dict = field(default_factory=dict)
    detection_matches: list = field(default_factory=list)
    remediation_actions: list = field(default_factory=list)
    ttl: int = field(default_factory=lambda: int(time.time()) + 90 * 86400)

    def to_dict(self) -> dict:
        # event_id and timestamp are DynamoDB keys — always include them
        data = asdict(self)
        result = {}
        for k, v in data.items():
            if k in ("event_id", "timestamp"):
                result[k] = _sanitize_for_dynamo(v) if v else k
            elif v:
                result[k] = _sanitize_for_dynamo(v)
        return result


@dataclass
class DetectionResult:
    rule_id: str
    rule_name: str
    severity: str
    matched: bool
    details: str = ""
    recommended_actions: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class RemediationRequest:
    event: SecurityEvent
    action: str
    parameters: dict = field(default_factory=dict)
    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    approved: bool = False
    dry_run: bool = True
    result: Optional[str] = None

    def to_dict(self) -> dict:
        data = asdict(self)
        data["event"] = self.event.to_dict()
        return data
