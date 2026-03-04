# HoloSecure

A serverless security monitoring platform built on AWS that detects, enriches, and responds to security events in real time. HoloSecure consumes events from CloudTrail, GuardDuty, VPC Flow Logs, and WAF through a Kinesis-backed pipeline, evaluates them against a pluggable detection engine, and executes guardrail-gated auto-remediation actions — blocking IPs, revoking credentials, isolating instances — without manual intervention.

Built for teams that need detection-to-response times measured in seconds, not tickets.

---

## Architecture

```
                              ┌─────────────────┐
                              │   CloudTrail     │
                              │   GuardDuty      │
                              │   VPC Flow Logs  │
                              │   WAF Logs       │
                              └────────┬────────┘
                                       │
                                       ▼
                            ┌─────────────────────┐
                            │   Kinesis Data       │
                            │   Stream (encrypted) │
                            └────────┬────────────┘
                                     │
                                     ▼
                          ┌────────────────────────┐
                          │  Ingestion Lambda       │
                          │  ─ parse & normalise    │
                          │  ─ store to DynamoDB    │
                          │  ─ archive to S3        │
                          └────────┬───────────────┘
                                   │
                                   ▼
                        ┌────────────────────────────┐
                        │  Detection Lambda           │
                        │  ─ rule engine (9 built-in) │
                        │  ─ YAML hot-reload rules    │
                        │  ─ severity classification   │
                        └───┬──────────────┬─────────┘
                            │              │
                   ┌────────▼───┐   ┌──────▼──────────┐
                   │ Enrichment │   │  Remediation     │
                   │ Lambda     │   │  Lambda          │
                   │ ─ GuardDuty│   │  ─ guardrails    │
                   │ ─ EC2/IAM  │   │  ─ IP blocking   │
                   │ ─ IP corr. │   │  ─ key revocation│
                   └────────────┘   │  ─ instance iso. │
                                    │  ─ user disable  │
                                    └──────┬──────────┘
                                           │
                                    ┌──────▼──────────┐
                                    │  Alerting Lambda │
                                    │  ─ SNS dispatch  │
                                    │  ─ Security Hub  │
                                    │    (ASFF export) │
                                    └─────────────────┘
```

### Data flow

1. **Ingest** — A Kinesis consumer Lambda reads batched records, auto-detects the source format (CloudTrail, GuardDuty, VPC Flow, WAF, or custom), and normalises them into a common `SecurityEvent` schema. Events are persisted to DynamoDB (with TTL) and archived to S3 with date-partitioned keys.

2. **Detect** — Events are evaluated against all active detection rules. Built-in rules cover unauthorized API calls, root account usage, IAM privilege escalation, security group misconfigurations, CloudTrail tampering, GuardDuty high-severity findings, brute-force login patterns, data exfiltration signals, and MFA deactivation. Additional rules can be defined in YAML and loaded from S3.

3. **Enrich** — Matched events are augmented with AWS resource context (EC2 tags, IAM user metadata), correlated GuardDuty findings, and recent-activity counts from DynamoDB. This context is written back to the event record for analyst review.

4. **Remediate** — The remediation engine supports five response actions: WAF IP blocking, IAM credential revocation, EC2 instance isolation, IAM user disablement, and IAM role quarantine. Every action passes through a guardrail chain (dry-run gate, severity threshold, IP allowlist, protected-account check) before execution.

5. **Alert** — Notifications are pushed to SNS with structured JSON payloads. High/critical findings are also exported to AWS Security Hub in ASFF format so they appear alongside native AWS security findings.

---

## Project Structure

```
HoloSecure/
├── template.yaml                    # SAM/CloudFormation — all infra as code
├── samconfig.toml                   # Deployment profiles (dev, prod)
├── Makefile                         # Build, test, deploy shortcuts
├── requirements.txt                 # Runtime dependencies
├── requirements-dev.txt             # Test dependencies (pytest, moto)
│
├── src/
│   ├── ingestion/
│   │   ├── handler.py               # Kinesis consumer Lambda
│   │   └── parsers.py               # Source-specific event parsers
│   │
│   ├── detection/
│   │   ├── handler.py               # Detection orchestrator Lambda
│   │   ├── engine.py                # Rule evaluation engine
│   │   └── rules.py                 # 9 built-in detection rules
│   │
│   ├── enrichment/
│   │   └── handler.py               # Context enrichment Lambda
│   │
│   ├── remediation/
│   │   ├── handler.py               # Remediation orchestrator Lambda
│   │   ├── actions.py               # Action implementations (WAF, IAM, EC2)
│   │   └── guardrails.py            # Safety checks before execution
│   │
│   ├── alerting/
│   │   └── handler.py               # SNS + Security Hub alerting
│   │
│   └── shared/
│       ├── models.py                # SecurityEvent, DetectionResult, enums
│       ├── aws_clients.py           # Lazy-init client pool (connection reuse)
│       └── logger.py                # Structured JSON logging for CW Insights
│
├── config/
│   ├── rules.yaml                   # Declarative detection rules
│   └── remediation_policies.yaml    # Remediation guardrail config
│
├── tests/
│   ├── conftest.py                  # Shared fixtures (realistic event payloads)
│   ├── unit/
│   │   ├── test_parsers.py          # Parser correctness (13 tests)
│   │   ├── test_detection_engine.py # Rule matching/false-positive (16 tests)
│   │   └── test_remediation.py      # Guardrails + action dispatch (9 tests)
│   └── integration/
│       └── test_pipeline.py         # End-to-end with moto (4 tests)
│
└── scripts/
    ├── deploy.sh                    # Validate → test → build → deploy
    └── simulate_events.py           # Push synthetic events to Kinesis
```

---

## Detection Rules

| ID | Rule | Severity | Auto-Remediation |
|---|---|---|---|
| HOLO-001 | Unauthorized API Call (AccessDenied) | MEDIUM | Revoke credentials |
| HOLO-002 | Root Account Activity | CRITICAL | Block IP |
| HOLO-003 | IAM Privilege Escalation | HIGH | Revoke creds + quarantine role |
| HOLO-004 | Security Group Open to World (0.0.0.0/0) | HIGH | — |
| HOLO-005 | CloudTrail Tampering (StopLogging, DeleteTrail) | CRITICAL | Revoke creds + disable user |
| HOLO-006 | GuardDuty High Severity Finding | HIGH/CRIT | Block IP |
| HOLO-007 | Console Login Brute Force | HIGH | Block IP |
| HOLO-008 | Potential Data Exfiltration (S3 exposure) | HIGH | Revoke credentials |
| HOLO-009 | MFA Deactivation | CRITICAL | Disable user + revoke creds |

Rules are pure functions with no side effects — adding a new rule means writing one function and registering it in `get_all_rules()`. YAML-based rules (`config/rules.yaml`) can be deployed to S3 without redeploying the Lambdas.

---

## Remediation Guardrails

Auto-remediation without guardrails is just automation with a gun. Every action passes through a sequential chain of safety checks:

| Guardrail | Purpose |
|---|---|
| **Dry-run gate** | Blocks all execution when `DRY_RUN=true` (default). Logs what *would* happen. |
| **Severity threshold** | Only auto-remediates events at or above a configurable severity (default: HIGH). |
| **IP allowlist** | Prevents blocking internal IPs, VPN exits, or known-good ranges. |
| **Protected accounts** | Never auto-revokes credentials for break-glass or CI deployer accounts. |

Dry-run is enabled by default. Flip it off in prod *after* you've validated the detection rules against your environment.

---

## Getting Started

### Prerequisites

- Python 3.12+
- AWS SAM CLI
- AWS account with appropriate permissions
- An existing Kinesis stream, or let the template create one

### Install and test

```bash
make install-dev    # install runtime + test dependencies
make test           # run the full suite (42 tests)
make test-cov       # run with coverage report
```

### Deploy

```bash
# First-time setup (interactive prompts for stack name, region, etc.)
./scripts/deploy.sh dev --guided

# Subsequent deploys
./scripts/deploy.sh dev

# Production
./scripts/deploy.sh prod
```

### Simulate events

```bash
# Push 10 random events (mix of benign and suspicious)
python scripts/simulate_events.py

# Simulate a brute-force attack (20 failed logins + 1 success)
python scripts/simulate_events.py --scenario brute

# Simulate a privilege escalation chain
python scripts/simulate_events.py --scenario privesc

# Custom volume
python scripts/simulate_events.py --count 100
```

---

## Design Decisions and Trade-offs

Documenting these explicitly because they matter more than the code.

**Event-driven, not polling.** Kinesis gives us sub-second delivery with replay capability. The trade-off is that Kinesis costs scale with shard-hours, not invocations — a low-traffic environment still pays the base shard cost (~$15/mo per shard).

**Async fan-out between stages.** The ingestion Lambda invokes detection asynchronously (`InvocationType=Event`). This decouples the stages and prevents a slow detection rule from causing Kinesis iterator age to spike. The trade-off is that a detection failure doesn't surface as an ingestion failure — you need to monitor each stage independently.

**DynamoDB for hot storage, S3 for cold.** Events live in DynamoDB (with GSIs on severity and source IP) for fast querying during active investigations. TTL expires them after 90 days. S3 holds the full archive with lifecycle transitions to IA (30d) and Glacier (90d). The trade-off is query complexity — you can't run ad-hoc SQL across both stores without something like Athena in front.

**Guardrails over approval workflows.** The system blocks unsafe actions rather than queuing them for human approval. This is simpler to implement and reason about, but it means that borderline situations get blocked rather than escalated. A future approval workflow (Step Functions + SNS) would address this.

**SAM over Terraform.** SAM is AWS-native and maps directly to CloudFormation, which makes it easier to reason about the infra alongside the Lambda code. The trade-off is that SAM is limited to AWS — if you need multi-cloud, Terraform or Pulumi is a better fit.

---

## Known Limitations

Being honest about gaps is more valuable than pretending they don't exist.

- **No cross-account support.** The current deployment targets a single AWS account. Multi-account architectures (AWS Organizations) would need a central event bus (EventBridge) or cross-account Kinesis access.

- **No stateful detection.** Rules evaluate events individually. Patterns like "5 failed logins from the same IP within 10 minutes" require a time-window aggregation layer (DynamoDB Streams + a windowing Lambda, or Kinesis Data Analytics) that isn't implemented yet.

- **Cold-start latency.** Lambda cold starts (especially with boto3 imports) can add 1-3 seconds to the first invocation. For the ingestion path this is acceptable; for remediation, SnapStart or provisioned concurrency would tighten it.

- **No approval workflow for critical actions.** Guardrails can block or allow, but there's no "hold for human approval" path. A Step Functions state machine with an SNS approval gate would cover this.

- **Single-region.** All resources deploy to one region. Active-active or failover requires replicating the Kinesis stream, DynamoDB Global Tables, and cross-region Lambda deployment.

- **No SIEM integration beyond Security Hub.** Events don't flow to Splunk, Elastic, or Sentinel. An S3-based export or Kinesis Firehose to an SIEM connector would close this gap.

- **YAML rules lack full expression power.** The current YAML schema supports basic field matching. Complex conditions (regex, nested field access, boolean combinators) require Python rules.

---

## Future Work

Tracked here rather than in issues so the roadmap is visible at a glance.

- [ ] **Stateful detection** — sliding-window aggregation for brute-force, port-scan, and volumetric anomaly detection using DynamoDB Streams or Kinesis Data Analytics
- [ ] **Approval workflows** — Step Functions state machine with SNS-based human approval for critical remediation actions
- [ ] **Multi-account event bus** — EventBridge-based ingestion from AWS Organizations member accounts
- [ ] **Threat intel feeds** — integration with AbuseIPDB, OTX, or custom STIX/TAXII feeds for IP reputation scoring during enrichment
- [ ] **Athena query layer** — partition the S3 archive in Parquet format and expose it through Athena for ad-hoc threat hunting
- [ ] **SIEM export** — Kinesis Firehose delivery stream to Splunk HEC, Elastic, or Sentinel
- [ ] **Provisioned concurrency** — for the remediation Lambda to eliminate cold-start delays on time-critical actions
- [ ] **Custom CloudWatch metrics** — publish detection counts, remediation rates, and mean-time-to-respond as custom metrics for operational dashboards
- [ ] **Infrastructure drift detection** — periodic Config rule evaluation to catch manual changes that bypass the pipeline
- [ ] **Terragrunt/CDK migration** — for teams that prefer those IaC tools over SAM/CloudFormation

---

## Security Considerations

- **Encryption at rest** — Kinesis stream, DynamoDB table, S3 buckets, and SNS topic all use KMS encryption.
- **Encryption in transit** — All AWS SDK calls use TLS. No custom HTTP endpoints are exposed.
- **Least privilege** — Each Lambda has its own scoped IAM policy. Remediation permissions are region-locked.
- **No secrets in code** — All configuration goes through environment variables and SSM Parameter Store. No API keys, no hardcoded credentials.
- **Audit trail** — Every remediation action (including blocked ones) is published to SNS for auditability.
- **Dry-run by default** — Remediation does nothing in production until you explicitly enable it after validation.

---

## Running Tests

```bash
# Full suite
make test

# With coverage
make test-cov

# Specific module
python -m pytest tests/unit/test_detection_engine.py -v
```

The test suite uses [moto](https://github.com/getmoto/moto) to mock AWS services. No real AWS resources are touched during testing.

---

## License

MIT
