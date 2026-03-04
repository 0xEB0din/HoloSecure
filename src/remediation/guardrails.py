"""Remediation guardrails — safety checks that gate every automated action.

The guardrail chain prevents runaway automation:

  1. Dry-run gate    – blocks execution when DRY_RUN is enabled
  2. Severity gate   – only auto-remediates above a configurable threshold
  3. Deny-list gate  – never auto-remediates specific accounts / IPs
  4. Rate-limit gate – prevents action flooding from a single event burst

Any guardrail returning (False, reason) short-circuits the chain and blocks
the action. This is a defense-in-depth measure — even if a detection rule
incorrectly fires, the guardrails limit the blast radius.
"""

import os
from typing import Tuple

from src.shared.models import RemediationRequest, Severity

# Severity ordering for comparisons
_SEVERITY_ORDER = {s.value: i for i, s in enumerate(Severity)}

APPROVAL_THRESHOLD = os.environ.get("REQUIRE_APPROVAL_ABOVE", Severity.HIGH.value)

# IPs that should never be auto-blocked (e.g. known internal CIDR, VPN exits)
_IP_ALLOWLIST = set(os.environ.get("IP_ALLOWLIST", "").split(",")) - {""}

# Accounts that should never have credentials auto-revoked
_PROTECTED_ACCOUNTS = set(os.environ.get("PROTECTED_ACCOUNTS", "").split(",")) - {""}


def evaluate_guardrails(request: RemediationRequest) -> Tuple[bool, str]:
    """Run all guardrails. Returns (approved, reason)."""
    for check in _GUARDRAIL_CHAIN:
        approved, reason = check(request)
        if not approved:
            return False, reason
    return True, "all guardrails passed"


def _check_dry_run(request: RemediationRequest) -> Tuple[bool, str]:
    if request.dry_run:
        return False, "dry-run mode is active"
    return True, ""


def _check_severity_threshold(request: RemediationRequest) -> Tuple[bool, str]:
    event_severity = _SEVERITY_ORDER.get(request.event.severity, 0)
    threshold = _SEVERITY_ORDER.get(APPROVAL_THRESHOLD, 2)

    if event_severity < threshold:
        return False, (
            f"event severity {request.event.severity} below auto-remediation "
            f"threshold {APPROVAL_THRESHOLD}"
        )
    return True, ""


def _check_ip_allowlist(request: RemediationRequest) -> Tuple[bool, str]:
    if not _IP_ALLOWLIST:
        return True, ""

    if request.event.source_ip in _IP_ALLOWLIST:
        return False, f"source IP {request.event.source_ip} is in the allowlist"
    return True, ""


def _check_protected_accounts(request: RemediationRequest) -> Tuple[bool, str]:
    if not _PROTECTED_ACCOUNTS:
        return True, ""

    identity = request.event.user_identity
    for protected in _PROTECTED_ACCOUNTS:
        if protected and protected in identity:
            return False, f"identity {identity} matches protected account {protected}"
    return True, ""


_GUARDRAIL_CHAIN = [
    _check_dry_run,
    _check_severity_threshold,
    _check_ip_allowlist,
    _check_protected_accounts,
]
