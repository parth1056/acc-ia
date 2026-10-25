# Policy-Driven Cloud Security Monitoring and Automated Remediation Using AWS

Advanced Cloud Computing IA-2, July-November 2026.



## What it does

The Python Lambda function reads a validated JSON policy from S3 and evaluates inbound rules on
two explicitly allowed, tagged security groups. Violations either generate an alert or cause
the specific rule to be revoked and its removal verified. CloudTrail and an EventBridge rule
provide configuration-change evaluation. EventBridge Scheduler independently invokes periodic scans.
CloudWatch records structured results; SNS publishes incident notifications.

Policies define protected ports/ranges, TCP/UDP/all protocols, unrestricted IPv4/IPv6 matching and
alert/remediate actions. Ports and actions are not embedded as separate SSH/database check functions.

## Start here

Read `docs/START-HERE.md`, then use `docs/DEMO-SCRIPT.md` for rehearsal and `docs/SUBMISSION.md`
for the submission fields. Raw, timestamped execution evidence is in the local `evidence/` directory (excluded from the public repository).

For the complete three-presenter recording, use `docs/RECORDING-RUNBOOK.md`.
Run `./demo.ps1 prepare` before recording, then `ssh`, `alert`, `policy` and `scheduled`
in that order. Run `./demo.ps1 finish` afterward. The helper verifies real trigger results
and restores the recording baseline after a full `./demo.ps1 rehearse`.

## Environment

- Windows PowerShell, Python 3.13, AWS CLI v2 and an authenticated owner profile.
- Profile: `acc-ia`; selected Region: `ap-southeast-2` (Sydney).
- CloudFormation stack: the stack configured in `deployment/private-runtime.json`.
- The notification email is configured privately at deployment and is independent of AWS sign-in/billing.
- No running EC2 instances, NAT gateways, databases or public application endpoints are required.

## Run locally

```powershell
uv venv .venv
uv pip install --python .venv\Scripts\python.exe -r requirements.txt
.venv\Scripts\python.exe -m unittest discover -s tests -v
.venv\Scripts\python.exe scripts\build.py
```

Infrastructure validation used cfn-lint 1.57.2 and official cfn-guard 3.2.1 with
`infra/security.guard`. The Guard checks are project-specific checks, not a full security audit.

```powershell
cfn-lint -t infra\template.json -r ap-southeast-2
cfn-guard validate --rules infra\security.guard --data infra\template.json --output-format json
```

## Rehearse against the existing deployment

Authenticate with `aws login --profile acc-ia --region ap-southeast-2` when needed.
The script uses short-lived login credentials through Boto3; no keys belong in this repository.

```powershell
.venv\Scripts\python.exe scripts\lab.py status
.venv\Scripts\python.exe scripts\lab.py policy v1
.venv\Scripts\python.exe scripts\lab.py events enable
.venv\Scripts\python.exe scripts\lab.py add ssh --group a
# Refresh the console and inspect the event-triggered CloudWatch summary.
.venv\Scripts\python.exe scripts\lab.py add database --group a
# The database rule remains and a notification is published.
.venv\Scripts\python.exe scripts\lab.py policy v2
.venv\Scripts\python.exe scripts\lab.py scan
# The same engine now removes the database rule without code redeployment.
```

For a genuine scheduled-path demonstration, disable event monitoring, add SSH to group B,
temporarily enable a one-minute scan, and wait for an actual `trigger=scheduled` log.
Then restore hourly scanning and the event rule. These demo controls change live settings;
restore the normal state after rehearsal.

```powershell
.venv\Scripts\python.exe scripts\lab.py events disable
.venv\Scripts\python.exe scripts\lab.py add ssh --group b
.venv\Scripts\python.exe scripts\lab.py schedule enable --rate 'rate(1 minute)'
# Wait for and verify the scheduled invocation before continuing.
.venv\Scripts\python.exe scripts\lab.py schedule enable --rate 'rate(1 hour)'
.venv\Scripts\python.exe scripts\lab.py events enable
.venv\Scripts\python.exe scripts\lab.py clear-demo
.venv\Scripts\python.exe scripts\lab.py policy v1
```

## Reproduce a deployment

1. Choose an accessible VPC in Sydney. Create a private, encrypted, versioned artifact bucket
   in the same Region and deny non-HTTPS access. The deployed bucket's name is in `deployment/private-runtime.json`.
2. Build with `scripts/build.py`. Upload `output/lambda.zip` under the code key in
   `output/build-manifest.json`; upload `config/policies.json` as `policies/current.json`.
3. Create a CloudFormation stack from `infra/template.json`, supplying VpcId, ArtifactBucket,
   CodeKey and NotificationEmail with `CAPABILITY_NAMED_IAM`. Review any validation failures.
4. Confirm the SNS email subscription. Initial parameters default to dry-run and disabled triggers.
5. Invoke the function manually, inspect logs, and verify scope. Update DryRun to false,
   ChangeMonitoringState to ENABLED, ScheduleState to ENABLED, ScanRate to rate(1 hour).

The template creates three unattached groups, the Lambda function and scoped execution role,
CloudWatch logs, an encrypted SNS topic/subscription, an active single-Region CloudTrail trail and
private log bucket, the event rule and invocation permission, and Scheduler with its invocation role.

## Boundaries and response semantics

- Inbound configuration only. A violation is not proof of an actual intrusion or network reachability.
- Public-anywhere means a single normalized `0.0.0.0/0` or `::/0` rule. Combined CIDR coverage,
  prefix lists, referenced groups, routing and NACL analysis are outside this prototype.
- A broad violating rule is removed in full, not rewritten into permitted fragments.
- A physical rule matching both alert and remediate policies remains alert-only, with a conflict flag.
- Changes require a configured group ID, monitoring tag and no attached network interfaces.
- Repeated events/scans can repeat alerts. No durable incident database or exactly-once guarantee.
- Current AWS state is re-read before removal, but concurrent changes remain possible between API calls.
- Invalid policy configuration stops evaluation, logs an error and makes the invocation fail.
- SNS acceptance proves publication. Email receipt requires a confirmed subscription and actual inbox evidence.
- Event delivery can be delayed or missed. Scheduled checks provide another evaluation opportunity.

## Costs and cleanup

The initial preflight on 20 October 2026 showed the Free plan, active, with USD 100 remaining.
That is a timestamped observation, not a guarantee about later balance. Monitor AWS Settings > Billing.
Lambda scans use 256 MB and a 90-second timeout; logs retain 14 days; trail objects expire after 30 days.

Keep the stack for rehearsal if needed. To pause automated checks use `lab.py events disable`
and `lab.py schedule disable`. Removing the stack requires a separate deliberate cleanup action.
CloudTrail's log bucket and the CloudWatch log group have Retain policies. The separately created
artifact bucket and versioned contents also remain after stack deletion; export evidence and
explicitly review retained resources before removing them. Never delete the default VPC.

## References

- https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-service-event-cloudtrail.html
- https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_RevokeSecurityGroupIngress.html
- https://docs.aws.amazon.com/vpc/latest/userguide/security-group-rules.html
- https://docs.aws.amazon.com/scheduler/latest/UserGuide/what-is-scheduler.html
- https://docs.aws.amazon.com/config/latest/developerguide/restricted-ssh.html

## Repository and verified results

Source repository: https://github.com/parth1056/acc-ia

Twenty-seven local tests passed again on 25 October 2026. Live AWS tests recorded on 20 and 24 October cover event-driven SSH remediation, alert-only database handling, dynamic policy changes, actual scheduled scans, IPv6 and port-range handling, monitoring scope, dry-run and invalid-policy validation. Received SNS emails for the database alert and policy-v2 remediation have also been verified.

The submission presentation explains these tests using real screenshots. Private deployment configuration, raw audit evidence, credentials and student details are intentionally excluded from this source repository. The course-specific GitHub Classroom acceptance/submission must be completed separately if required by the instructor.
