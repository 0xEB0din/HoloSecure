"""Lazy-initialised AWS service clients.

Clients are created once per Lambda execution environment and reused across
invocations to take advantage of connection pooling.
"""

import boto3
import os

_region = os.environ.get("AWS_REGION", "us-east-1")

_clients: dict = {}


def _get(service: str):
    if service not in _clients:
        _clients[service] = boto3.client(service, region_name=_region)
    return _clients[service]


def dynamodb():
    return _get("dynamodb")


def dynamodb_resource():
    if "dynamodb_resource" not in _clients:
        _clients["dynamodb_resource"] = boto3.resource(
            "dynamodb", region_name=_region
        )
    return _clients["dynamodb_resource"]


def s3():
    return _get("s3")


def sns():
    return _get("sns")


def lambda_client():
    return _get("lambda")


def ec2():
    return _get("ec2")


def iam():
    return _get("iam")


def wafv2():
    return _get("wafv2")


def guardduty():
    return _get("guardduty")


def securityhub():
    return _get("securityhub")
