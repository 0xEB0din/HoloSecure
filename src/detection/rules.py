"""Built-in detection rules.

Each rule is a callable that accepts a SecurityEvent and returns either a
DetectionResult (match) or None (no match). Rules are registered via
``get_all_rules()`` so the engine picks them up automatically.

Design note — rules are intentionally kept as pure functions with no side
effects. This makes them trivially testable and allows the engine to run
them concurrently in a future iteration.
"""

from typing import Optional, List, Callable
from src.shared.models import SecurityEvent, DetectionResult, Severity, RemediationAction

RuleFn = Callable[[SecurityEvent], Optional[DetectionResult]]


def get_all_rules() -> List[RuleFn]:
    return [
        detect_unauthorized_api_calls,
        detect_root_account_usage,
        detect_iam_privilege_escalation,
        detect_security_group_open_ingress,
        detect_cloudtrail_tampering,
        detect_guardduty_high_severity,
        detect_brute_force_pattern,
        detect_data_exfiltration_signals,
        detect_mfa_deactivation,
    ]


# ── Rules ──────────────────────────────────────────────────────────────


def detect_unauthorized_api_calls(event: SecurityEvent) -> Optional[DetectionResult]:
    """Flag API calls that returned AccessDenied or UnauthorizedAccess."""
    error_code = event.raw_event.get("errorCode", "")
    if error_code not in ("AccessDenied", "Client.UnauthorizedAccess", "UnauthorizedAccess"):
        return None

    return DetectionResult(
        rule_id="HOLO-001",
        rule_name="Unauthorized API Call",
        severity=Severity.MEDIUM.value,
        matched=True,
        details=f"API call {event.event_type} denied for {event.user_identity}",
        recommended_actions=[RemediationAction.REVOKE_CREDENTIALS.value],
    )


def detect_root_account_usage(event: SecurityEvent) -> Optional[DetectionResult]:
    """Any console or API activity from the root account is suspicious."""
    user_identity = event.raw_event.get("userIdentity", {})
    if user_identity.get("type") != "Root":
        return None

    return DetectionResult(
        rule_id="HOLO-002",
        rule_name="Root Account Activity",
        severity=Severity.CRITICAL.value,
        matched=True,
        details=f"Root account used for {event.event_type} from {event.source_ip}",
        recommended_actions=[RemediationAction.BLOCK_IP.value],
    )


def detect_iam_privilege_escalation(event: SecurityEvent) -> Optional[DetectionResult]:
    """Detect attempts to escalate IAM privileges."""
    escalation_actions = {
        "AttachUserPolicy", "AttachRolePolicy", "PutUserPolicy",
        "PutRolePolicy", "CreatePolicyVersion", "SetDefaultPolicyVersion",
        "AddUserToGroup", "CreateLoginProfile", "UpdateLoginProfile",
        "AttachGroupPolicy", "PutGroupPolicy", "CreateAccessKey",
    }
    if event.event_type not in escalation_actions:
        return None

    return DetectionResult(
        rule_id="HOLO-003",
        rule_name="IAM Privilege Escalation",
        severity=Severity.HIGH.value,
        matched=True,
        details=f"Privilege escalation via {event.event_type} by {event.user_identity}",
        recommended_actions=[
            RemediationAction.REVOKE_CREDENTIALS.value,
            RemediationAction.QUARANTINE_ROLE.value,
        ],
    )


def detect_security_group_open_ingress(event: SecurityEvent) -> Optional[DetectionResult]:
    """Detect security group rules that open 0.0.0.0/0 ingress."""
    if event.event_type != "AuthorizeSecurityGroupIngress":
        return None

    params = event.raw_event.get("requestParameters", {})
    ip_permissions = params.get("ipPermissions", {}).get("items", [])

    for perm in ip_permissions:
        for ip_range in perm.get("ipRanges", {}).get("items", []):
            if ip_range.get("cidrIp") == "0.0.0.0/0":
                return DetectionResult(
                    rule_id="HOLO-004",
                    rule_name="Security Group Open to World",
                    severity=Severity.HIGH.value,
                    matched=True,
                    details=f"SG opened 0.0.0.0/0 ingress on port(s) "
                            f"{perm.get('fromPort', '*')}-{perm.get('toPort', '*')}",
                    recommended_actions=[],
                )
    return None


def detect_cloudtrail_tampering(event: SecurityEvent) -> Optional[DetectionResult]:
    """Detect attempts to disable or delete CloudTrail logging."""
    tampering_actions = {"StopLogging", "DeleteTrail", "UpdateTrail", "PutEventSelectors"}
    if event.event_type not in tampering_actions:
        return None

    return DetectionResult(
        rule_id="HOLO-005",
        rule_name="CloudTrail Tampering",
        severity=Severity.CRITICAL.value,
        matched=True,
        details=f"CloudTrail {event.event_type} by {event.user_identity}",
        recommended_actions=[
            RemediationAction.REVOKE_CREDENTIALS.value,
            RemediationAction.DISABLE_USER.value,
        ],
    )


def detect_guardduty_high_severity(event: SecurityEvent) -> Optional[DetectionResult]:
    """Escalate high/critical GuardDuty findings."""
    if event.source != "guardduty":
        return None

    severity_score = event.raw_event.get("detail", {}).get("severity", 0)
    if severity_score < 7.0:
        return None

    return DetectionResult(
        rule_id="HOLO-006",
        rule_name="GuardDuty High Severity Finding",
        severity=Severity.from_score(severity_score).value,
        matched=True,
        details=f"GuardDuty finding: {event.event_type} (score: {severity_score})",
        recommended_actions=[RemediationAction.BLOCK_IP.value],
    )


def detect_brute_force_pattern(event: SecurityEvent) -> Optional[DetectionResult]:
    """Detect ConsoleLogin failures which may indicate brute-force attempts."""
    if event.event_type != "ConsoleLogin":
        return None
    response = event.raw_event.get("responseElements", {})
    if response.get("ConsoleLogin") != "Failure":
        return None

    return DetectionResult(
        rule_id="HOLO-007",
        rule_name="Console Login Brute Force",
        severity=Severity.HIGH.value,
        matched=True,
        details=f"Failed console login from {event.source_ip} for {event.user_identity}",
        recommended_actions=[RemediationAction.BLOCK_IP.value],
    )


def detect_data_exfiltration_signals(event: SecurityEvent) -> Optional[DetectionResult]:
    """Detect S3 bulk-download or public access changes that may indicate exfiltration."""
    exfil_actions = {
        "PutBucketPolicy", "PutBucketAcl", "PutObjectAcl",
        "DeleteBucketEncryption", "PutBucketPublicAccessBlock",
    }
    if event.event_type not in exfil_actions:
        return None

    return DetectionResult(
        rule_id="HOLO-008",
        rule_name="Potential Data Exfiltration",
        severity=Severity.HIGH.value,
        matched=True,
        details=f"Data exposure risk: {event.event_type} by {event.user_identity}",
        recommended_actions=[RemediationAction.REVOKE_CREDENTIALS.value],
    )


def detect_mfa_deactivation(event: SecurityEvent) -> Optional[DetectionResult]:
    """Detect MFA device deactivation — common precursor to account takeover."""
    if event.event_type != "DeactivateMFADevice":
        return None

    return DetectionResult(
        rule_id="HOLO-009",
        rule_name="MFA Deactivation",
        severity=Severity.CRITICAL.value,
        matched=True,
        details=f"MFA deactivated for {event.user_identity} from {event.source_ip}",
        recommended_actions=[
            RemediationAction.DISABLE_USER.value,
            RemediationAction.REVOKE_CREDENTIALS.value,
        ],
    )
