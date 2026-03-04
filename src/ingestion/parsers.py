"""Event parsers — normalise raw events from different AWS sources into
the common SecurityEvent schema.

Each parser handles the idiosyncrasies of its source format (CloudTrail's
nested userIdentity, VPC Flow Log field ordering, GuardDuty finding
structure, etc.) and produces a uniform SecurityEvent.
"""

from datetime import datetime, timezone

from src.shared.models import SecurityEvent, EventSource, Severity


def parse_event(raw: dict) -> SecurityEvent:
    """Route a raw event to the correct source-specific parser."""
    source = _detect_source(raw)
    parser = _PARSERS.get(source, _parse_generic)
    return parser(raw)


def _detect_source(raw: dict) -> str:
    """Infer the event source from the payload structure."""
    if "detail-type" in raw and raw.get("source") == "aws.guardduty":
        return EventSource.GUARDDUTY.value
    if "eventVersion" in raw and "eventSource" in raw:
        return EventSource.CLOUDTRAIL.value
    if "version" in raw and "interface-id" in raw:
        return EventSource.VPC_FLOW.value
    if raw.get("source") == "aws.waf":
        return EventSource.WAF.value
    return EventSource.CUSTOM.value


def _parse_cloudtrail(raw: dict) -> SecurityEvent:
    user_identity = raw.get("userIdentity", {})
    return SecurityEvent(
        source=EventSource.CLOUDTRAIL.value,
        event_type=raw.get("eventName", "Unknown"),
        source_ip=raw.get("sourceIPAddress", "0.0.0.0"),
        timestamp=raw.get("eventTime") or datetime.now(timezone.utc).isoformat(),
        account_id=raw.get("recipientAccountId", ""),
        region=raw.get("awsRegion", ""),
        resource_arn=_extract_resource_arn(raw),
        user_identity=user_identity.get("arn", user_identity.get("userName", "")),
        severity=_classify_cloudtrail_severity(raw),
        raw_event=raw,
    )


def _parse_guardduty(raw: dict) -> SecurityEvent:
    detail = raw.get("detail", {})
    service = detail.get("service", {})
    action = service.get("action", {})

    source_ip = "0.0.0.0"
    network_info = action.get("networkConnectionAction", {})
    if network_info:
        source_ip = network_info.get("remoteIpDetails", {}).get("ipAddressV4", source_ip)

    severity_score = detail.get("severity", 0)

    return SecurityEvent(
        source=EventSource.GUARDDUTY.value,
        event_type=detail.get("type", "Unknown"),
        source_ip=source_ip,
        timestamp=detail.get("updatedAt") or raw.get("time") or datetime.now(timezone.utc).isoformat(),
        account_id=detail.get("accountId", ""),
        region=detail.get("region", ""),
        resource_arn=detail.get("resource", {}).get("instanceDetails", {}).get(
            "instanceId", ""
        ),
        severity=Severity.from_score(severity_score).value,
        raw_event=raw,
    )


def _parse_vpc_flow(raw: dict) -> SecurityEvent:
    return SecurityEvent(
        source=EventSource.VPC_FLOW.value,
        event_type="VPCFlowLog",
        source_ip=raw.get("srcaddr", raw.get("source-ip", "0.0.0.0")),
        account_id=raw.get("account-id", ""),
        region=raw.get("region", ""),
        severity=Severity.LOW.value,
        raw_event=raw,
    )


def _parse_waf(raw: dict) -> SecurityEvent:
    detail = raw.get("detail", {})
    return SecurityEvent(
        source=EventSource.WAF.value,
        event_type=detail.get("action", "WAFEvent"),
        source_ip=detail.get("httpRequest", {}).get("clientIp", "0.0.0.0"),
        account_id=raw.get("account", ""),
        region=raw.get("region", ""),
        severity=Severity.MEDIUM.value,
        raw_event=raw,
    )


def _parse_generic(raw: dict) -> SecurityEvent:
    return SecurityEvent(
        source=raw.get("source", EventSource.CUSTOM.value),
        event_type=raw.get("event_type", raw.get("type", "Unknown")),
        source_ip=raw.get("source_ip", raw.get("sourceIPAddress", "0.0.0.0")),
        severity=raw.get("severity", Severity.LOW.value),
        raw_event=raw,
    )


def _extract_resource_arn(cloudtrail_event: dict) -> str:
    resources = cloudtrail_event.get("resources", [])
    if resources:
        return resources[0].get("ARN", "")
    return ""


def _classify_cloudtrail_severity(event: dict) -> str:
    """Heuristic severity classification for CloudTrail events."""
    event_name = event.get("eventName", "").lower()
    error_code = event.get("errorCode", "")

    high_risk_actions = {
        "deletebucket", "deletetrail", "stoplogging",
        "putbucketpolicy", "putrolepolicy", "createaccesskey",
        "attachrolepolicy", "deactivatemfadevice",
        "authorizesecuritygroupingress", "createloginprofile",
    }

    if event_name in high_risk_actions:
        return Severity.HIGH.value
    if error_code in ("UnauthorizedAccess", "AccessDenied", "Client.UnauthorizedAccess"):
        return Severity.MEDIUM.value
    if "delete" in event_name or "remove" in event_name:
        return Severity.MEDIUM.value
    return Severity.LOW.value


_PARSERS = {
    EventSource.CLOUDTRAIL.value: _parse_cloudtrail,
    EventSource.GUARDDUTY.value: _parse_guardduty,
    EventSource.VPC_FLOW.value: _parse_vpc_flow,
    EventSource.WAF.value: _parse_waf,
    EventSource.CUSTOM.value: _parse_generic,
}
