#!/usr/bin/env python3
"""Event simulator — generates realistic security events and pushes them
to the Kinesis stream for end-to-end testing.

Usage:
    python scripts/simulate_events.py                   # 10 random events
    python scripts/simulate_events.py --count 50        # 50 random events
    python scripts/simulate_events.py --scenario brute  # brute-force scenario
"""

import argparse
import json
import random
import uuid
from datetime import datetime, timezone

import boto3


STREAM_NAME = "holosecure-events-dev"
REGION = "us-east-1"

SUSPICIOUS_IPS = [
    "198.51.100.42", "203.0.113.50", "192.0.2.99",
    "198.51.100.200", "203.0.113.17",
]
INTERNAL_IPS = ["10.0.1.15", "10.0.2.30", "172.16.0.5"]
IAM_USERS = ["dev-alice", "dev-bob", "ci-deployer", "admin-carol"]

# ── Event generators ────────────────────────────────────────────────


def _cloudtrail_normal():
    return {
        "eventVersion": "1.08",
        "eventSource": "ec2.amazonaws.com",
        "eventName": random.choice(["DescribeInstances", "DescribeSecurityGroups", "ListBuckets"]),
        "awsRegion": REGION,
        "sourceIPAddress": random.choice(INTERNAL_IPS),
        "userIdentity": {
            "type": "IAMUser",
            "arn": f"arn:aws:iam::123456789012:user/{random.choice(IAM_USERS)}",
        },
        "recipientAccountId": "123456789012",
        "errorCode": "",
    }


def _cloudtrail_suspicious():
    action = random.choice([
        "CreateAccessKey", "AttachRolePolicy", "PutBucketPolicy",
        "AuthorizeSecurityGroupIngress", "StopLogging",
    ])
    return {
        "eventVersion": "1.08",
        "eventSource": "iam.amazonaws.com",
        "eventName": action,
        "awsRegion": REGION,
        "sourceIPAddress": random.choice(SUSPICIOUS_IPS),
        "userIdentity": {
            "type": "IAMUser",
            "arn": f"arn:aws:iam::123456789012:user/{random.choice(IAM_USERS)}",
        },
        "recipientAccountId": "123456789012",
        "errorCode": "",
        "requestParameters": {
            "userName": random.choice(IAM_USERS),
            "ipPermissions": {
                "items": [{"fromPort": 22, "toPort": 22, "ipRanges": {"items": [{"cidrIp": "0.0.0.0/0"}]}}]
            } if action == "AuthorizeSecurityGroupIngress" else {},
        },
    }


def _guardduty_finding():
    return {
        "source": "aws.guardduty",
        "detail-type": "GuardDuty Finding",
        "detail": {
            "type": random.choice([
                "UnauthorizedAccess:EC2/MaliciousIPCaller.Custom",
                "Recon:EC2/PortProbeUnprotectedPort",
                "CryptoCurrency:EC2/BitcoinTool.B!DNS",
            ]),
            "severity": random.choice([3.0, 5.0, 7.5, 8.0, 9.2]),
            "accountId": "123456789012",
            "region": REGION,
            "updatedAt": datetime.now(timezone.utc).isoformat(),
            "resource": {"instanceDetails": {"instanceId": f"i-{uuid.uuid4().hex[:17]}"}},
            "service": {
                "action": {
                    "networkConnectionAction": {
                        "remoteIpDetails": {"ipAddressV4": random.choice(SUSPICIOUS_IPS)}
                    }
                }
            },
        },
    }


def _brute_force_login():
    ip = random.choice(SUSPICIOUS_IPS)
    target = random.choice(IAM_USERS)
    return {
        "eventVersion": "1.08",
        "eventSource": "signin.amazonaws.com",
        "eventName": "ConsoleLogin",
        "awsRegion": REGION,
        "sourceIPAddress": ip,
        "userIdentity": {
            "type": "IAMUser",
            "arn": f"arn:aws:iam::123456789012:user/{target}",
        },
        "recipientAccountId": "123456789012",
        "responseElements": {"ConsoleLogin": "Failure"},
    }


def _root_login():
    return {
        "eventVersion": "1.08",
        "eventSource": "signin.amazonaws.com",
        "eventName": "ConsoleLogin",
        "awsRegion": REGION,
        "sourceIPAddress": random.choice(SUSPICIOUS_IPS),
        "userIdentity": {"type": "Root", "arn": "arn:aws:iam::123456789012:root"},
        "recipientAccountId": "123456789012",
        "responseElements": {"ConsoleLogin": "Success"},
    }


# ── Scenarios ────────────────────────────────────────────────────────

def random_events(count: int) -> list:
    generators = [
        (_cloudtrail_normal, 0.4),
        (_cloudtrail_suspicious, 0.25),
        (_guardduty_finding, 0.15),
        (_brute_force_login, 0.1),
        (_root_login, 0.1),
    ]
    events = []
    for _ in range(count):
        gen = random.choices(
            [g for g, _ in generators],
            weights=[w for _, w in generators],
        )[0]
        events.append(gen())
    return events


def brute_force_scenario() -> list:
    """Simulate a brute-force attack: 20 failed logins then a success."""
    ip = "198.51.100.42"
    target = "admin-carol"
    events = []
    for _ in range(20):
        evt = _brute_force_login()
        evt["sourceIPAddress"] = ip
        evt["userIdentity"]["arn"] = f"arn:aws:iam::123456789012:user/{target}"
        events.append(evt)
    # Final successful login
    success = _brute_force_login()
    success["sourceIPAddress"] = ip
    success["responseElements"]["ConsoleLogin"] = "Success"
    events.append(success)
    return events


def privilege_escalation_scenario() -> list:
    """Simulate privilege escalation: create key → attach admin policy → exfil."""
    ip = "198.51.100.200"
    user = "dev-bob"
    base = {
        "eventVersion": "1.08",
        "awsRegion": REGION,
        "sourceIPAddress": ip,
        "userIdentity": {
            "type": "IAMUser",
            "arn": f"arn:aws:iam::123456789012:user/{user}",
        },
        "recipientAccountId": "123456789012",
        "errorCode": "",
    }
    return [
        {**base, "eventSource": "iam.amazonaws.com", "eventName": "CreateAccessKey"},
        {**base, "eventSource": "iam.amazonaws.com", "eventName": "AttachUserPolicy"},
        {**base, "eventSource": "s3.amazonaws.com", "eventName": "PutBucketPolicy"},
        {**base, "eventSource": "s3.amazonaws.com", "eventName": "GetObject"},
    ]


SCENARIOS = {
    "random": random_events,
    "brute": lambda: brute_force_scenario(),
    "privesc": lambda: privilege_escalation_scenario(),
}

# ── Main ─────────────────────────────────────────────────────────────


def push_events(events: list, stream: str, region: str):
    kinesis = boto3.client("kinesis", region_name=region)
    records = [
        {
            "Data": json.dumps(evt).encode(),
            "PartitionKey": str(uuid.uuid4()),
        }
        for evt in events
    ]
    # Kinesis PutRecords supports max 500 per call
    for i in range(0, len(records), 500):
        batch = records[i : i + 500]
        resp = kinesis.put_records(Records=batch, StreamName=stream)
        failed = resp.get("FailedRecordCount", 0)
        print(f"  Pushed {len(batch)} records ({failed} failed)")


def main():
    parser = argparse.ArgumentParser(description="HoloSecure event simulator")
    parser.add_argument("--count", type=int, default=10, help="Number of random events")
    parser.add_argument("--scenario", choices=list(SCENARIOS.keys()), default="random")
    parser.add_argument("--stream", default=STREAM_NAME)
    parser.add_argument("--region", default=REGION)
    args = parser.parse_args()

    print(f"Generating events (scenario={args.scenario})...")
    if args.scenario == "random":
        events = random_events(args.count)
    else:
        events = SCENARIOS[args.scenario]()

    print(f"Pushing {len(events)} events to {args.stream}...")
    push_events(events, args.stream, args.region)
    print("Done.")


if __name__ == "__main__":
    main()
