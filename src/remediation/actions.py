"""Remediation action implementations.

Each action operates against a specific AWS service to contain a threat.
All actions respect the ``dry_run`` flag on the request — when dry-run is
enabled, the action logs what *would* happen without making changes.
"""

from src.shared.logger import get_logger
from src.shared.models import RemediationRequest, RemediationAction
from src.shared import aws_clients

logger = get_logger(__name__)


def execute_action(request: RemediationRequest) -> str:
    executor = _ACTION_MAP.get(request.action)
    if not executor:
        return f"UNKNOWN_ACTION: {request.action}"
    return executor(request)


def _block_ip(request: RemediationRequest) -> str:
    """Add the source IP to a WAF IP set for blocking."""
    ip = request.event.source_ip
    if not ip or ip == "0.0.0.0":
        return "SKIPPED: no valid source IP"

    if request.dry_run:
        return f"DRY_RUN: would block IP {ip} in WAF IP set"

    ip_set_name = request.parameters.get("ip_set_name", "holosecure-blocklist")
    ip_set_id = request.parameters.get("ip_set_id", "")

    if not ip_set_id:
        return "SKIPPED: no WAF IP set configured"

    waf = aws_clients.wafv2()
    resp = waf.get_ip_set(Name=ip_set_name, Scope="REGIONAL", Id=ip_set_id)
    addresses = resp["IPSet"]["Addresses"]
    lock_token = resp["LockToken"]

    cidr = f"{ip}/32"
    if cidr in addresses:
        return f"ALREADY_BLOCKED: {ip}"

    addresses.append(cidr)
    waf.update_ip_set(
        Name=ip_set_name,
        Scope="REGIONAL",
        Id=ip_set_id,
        Addresses=addresses,
        LockToken=lock_token,
    )
    return f"BLOCKED: {ip} added to WAF IP set {ip_set_name}"


def _revoke_credentials(request: RemediationRequest) -> str:
    """Deactivate all access keys for the IAM user."""
    user_identity = request.event.user_identity
    if not user_identity:
        return "SKIPPED: no user identity"

    username = user_identity.split("/")[-1]

    if request.dry_run:
        return f"DRY_RUN: would revoke access keys for {username}"

    iam = aws_clients.iam()
    keys = iam.list_access_keys(UserName=username).get("AccessKeyMetadata", [])
    revoked = 0

    for key in keys:
        if key["Status"] == "Active":
            iam.update_access_key(
                UserName=username,
                AccessKeyId=key["AccessKeyId"],
                Status="Inactive",
            )
            revoked += 1

    return f"REVOKED: {revoked} access key(s) for {username}"


def _isolate_instance(request: RemediationRequest) -> str:
    """Replace the instance's security groups with an isolation SG that
    blocks all inbound/outbound traffic."""
    instance_id = request.event.resource_arn
    if not instance_id or not instance_id.startswith("i-"):
        return "SKIPPED: no valid instance ID"

    if request.dry_run:
        return f"DRY_RUN: would isolate instance {instance_id}"

    ec2 = aws_clients.ec2()

    # Look up the instance's VPC to find or create the isolation SG
    desc = ec2.describe_instances(InstanceIds=[instance_id])
    instance = desc["Reservations"][0]["Instances"][0]
    vpc_id = instance["VpcId"]

    isolation_sg = _get_or_create_isolation_sg(ec2, vpc_id)

    ec2.modify_instance_attribute(
        InstanceId=instance_id,
        Groups=[isolation_sg],
    )
    return f"ISOLATED: instance {instance_id} moved to isolation SG {isolation_sg}"


def _disable_user(request: RemediationRequest) -> str:
    """Attach an explicit deny-all policy to the user."""
    user_identity = request.event.user_identity
    if not user_identity:
        return "SKIPPED: no user identity"

    username = user_identity.split("/")[-1]

    if request.dry_run:
        return f"DRY_RUN: would disable user {username}"

    deny_policy = '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}'
    aws_clients.iam().put_user_policy(
        UserName=username,
        PolicyName="HoloSecure-EmergencyDenyAll",
        PolicyDocument=deny_policy,
    )
    return f"DISABLED: deny-all policy attached to {username}"


def _quarantine_role(request: RemediationRequest) -> str:
    """Attach a deny-all inline policy to the assumed role."""
    user_identity = request.event.user_identity
    if not user_identity:
        return "SKIPPED: no user identity"

    # Extract role name from ARN like arn:aws:sts::123456:assumed-role/RoleName/session
    parts = user_identity.split("/")
    if len(parts) < 2:
        return "SKIPPED: could not extract role name"
    role_name = parts[-2] if "assumed-role" in user_identity else parts[-1]

    if request.dry_run:
        return f"DRY_RUN: would quarantine role {role_name}"

    deny_policy = '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}'
    aws_clients.iam().put_role_policy(
        RoleName=role_name,
        PolicyName="HoloSecure-Quarantine",
        PolicyDocument=deny_policy,
    )
    return f"QUARANTINED: deny-all policy attached to role {role_name}"


def _get_or_create_isolation_sg(ec2, vpc_id: str) -> str:
    sg_name = "holosecure-isolation"
    existing = ec2.describe_security_groups(
        Filters=[
            {"Name": "group-name", "Values": [sg_name]},
            {"Name": "vpc-id", "Values": [vpc_id]},
        ]
    )
    if existing["SecurityGroups"]:
        return existing["SecurityGroups"][0]["GroupId"]

    resp = ec2.create_security_group(
        GroupName=sg_name,
        Description="HoloSecure isolation SG - blocks all traffic",
        VpcId=vpc_id,
    )
    sg_id = resp["GroupId"]

    # Revoke the default egress rule
    ec2.revoke_security_group_egress(
        GroupId=sg_id,
        IpPermissions=[{
            "IpProtocol": "-1",
            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
        }],
    )
    return sg_id


_ACTION_MAP = {
    RemediationAction.BLOCK_IP.value: _block_ip,
    RemediationAction.REVOKE_CREDENTIALS.value: _revoke_credentials,
    RemediationAction.ISOLATE_INSTANCE.value: _isolate_instance,
    RemediationAction.DISABLE_USER.value: _disable_user,
    RemediationAction.QUARANTINE_ROLE.value: _quarantine_role,
}
