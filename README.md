# Policy-Driven Cloud Security Monitoring and Automated Remediation Using AWS

A serverless prototype that checks AWS security group inbound rules against external JSON policies, alerts on violations, and automatically removes selected unsafe rules.

For example, public SSH access triggers automatic removal, while a public database port produces an administrator alert. Changing the policy in S3 changes the response without redeploying Lambda code.

## How it works

```text
Security group rule added or modified
                 |
       CloudTrail -> EventBridge
                           |
Hourly Scheduler --------> Lambda <-------- Manual invocation
                           |
                 Read JSON policy from S3
                           |
                 Inspect current EC2 rules
                           |
                 Match ports / protocol / source
                           |
            +--------------+--------------+
            |                             |
         Alert only                 Remediate
      Keep the rule          Recheck scope and current rule
            |                Revoke the exact rule ID
            |                Verify the rule is absent
            +--------------+--------------+
                           |
               CloudWatch logs + SNS notification
```

CloudTrail records configuration changes. EventBridge invokes the evaluator after supported ingress additions or modifications. Scheduler independently checks both monitored groups. Every evaluation loads the current policy from S3.

This is configuration monitoring: it does not inspect network traffic or detect an actual intrusion. The demonstration uses **unattached test security groups**, with no running EC2 instances or database servers.

## Policy behavior and demonstrated results

The checked-in [policy](config/policies.json) is `demo-v1`:

| Policy | TCP ports | Public source | Response |
|---|---|---|---|
| ADMIN-ACCESS | 22, 3389 | `0.0.0.0/0` or `::/0` | Remove and verify |
| DATABASE-ACCESS | 3306, 5432 | `0.0.0.0/0` or `::/0` | Alert; retain rule |

For the policy-change experiment, `demo-v2` changes DATABASE-ACCESS to `remediate`. A subsequent manual scan removes the same database rule previously retained under v1. Uploading a policy alone does **not** trigger a scan. The Lambda code hash stays unchanged.

Live AWS tests recorded on 20 and 24 October 2026 demonstrated:

- Event-triggered SSH removal, with post-removal verification.
- Database alert-only handling, followed by remediation after the S3 policy change.
- Actual scheduled evaluation, public IPv6 handling, and overlapping port-range detection.
- Preservation of restricted SSH, unmatched HTTPS, and an unmonitored control group.
- Dry-run behavior and rejection of invalid policy configuration.
- Received SNS incident emails for the database alert and subsequent remediation.

The [sanitized rehearsal summary](docs/demo-verification.json) records the main live scenarios. **All 27 local unit tests passed again on 25 October 2026**: 17 evaluator tests and 10 workflow tests. These tests use mocks; they do not deploy resources or contact AWS. Historical verification is not a claim about the current health of a deployment.

## Repository map

| Path | Purpose |
|---|---|
| [src/policy_engine.py](src/policy_engine.py) | Policy validation, protocol/source/range matching and response conflicts |
| [src/handler.py](src/handler.py) | AWS reads, scope checks, evaluation, remediation, verification, logging and notifications |
| [config/policies.json](config/policies.json) | Baseline external policy |
| [scripts/build.py](scripts/build.py) | Lambda packaging and CloudFormation generation |
| [infra/template.json](infra/template.json) | Infrastructure, initially dry-run with automatic evaluation disabled |
| [infra/security.guard](infra/security.guard) | Project-specific infrastructure checks |
| [tests/](tests/) | Evaluator and workflow tests |
| [scripts/demo.py](scripts/demo.py), [demo.ps1](demo.ps1) | Ordered live rehearsal, verification and restoration |
| [scripts/lab.py](scripts/lab.py) | Individual live status, policy, rule, scan and trigger controls |
| [docs/IMPLEMENTATION.md](docs/IMPLEMENTATION.md) | Short implementation overview |
| [docs/RECORDING-RUNBOOK.md](docs/RECORDING-RUNBOOK.md) | Optional live evidence-capture and rehearsal instructions |

## Run locally

Prerequisites: Git and Python 3.13. These examples use Windows PowerShell, matching the development environment. AWS credentials are unnecessary for the unit tests and build.

```powershell
git clone https://github.com/parth1056/acc-ia.git
Set-Location acc-ia
py -3.13 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
.\.venv\Scripts\python.exe scripts\build.py
```

The build produces `output/lambda.zip`, `output/build-manifest.json`, and regenerates `infra/template.json`. The archive contains the application modules; Lambda supplies Boto3 in its managed Python runtime. Local pinned dependencies support tests and operator helpers. The build derives the S3 code key from the archive hash, so rebuilding can change the template's default CodeKey.

Optional infrastructure checks (install cfn-guard separately):

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
.\.venv\Scripts\cfn-lint.exe -t infra\template.json -r ap-southeast-2
cfn-guard validate --rules infra\security.guard --data infra\template.json --output-format json
```

The Guard rules check this project's requirements; they are not a complete security audit.

## Deploy your own copy

The supplied helpers use **ap-southeast-2 (Sydney)**. For the new AWS experience, confirm Sydney is your project's selected Region in AWS Settings > View all projects > Overview > Additional Info > Region before following these steps.

You need an authorized AWS project, current AWS CLI v2 credentials, an existing VPC in Sydney, and permission to create the resources described below. This repository does not provide access to the original deployment. Never put credentials or signed URLs in source files.

1. Authenticate your local profile. For the browser-login setup used here:

   ```powershell
   aws login --profile acc-ia --region ap-southeast-2
   aws sts get-caller-identity --profile acc-ia --region ap-southeast-2
   ```

   An already authenticated CLI profile is also usable. `acc-ia` is a local profile label.

2. Create an artifact bucket in Sydney with a globally unique name. Enable all four S3 Block Public Access settings, default encryption and versioning. Add a bucket policy denying non-HTTPS access. Its policies must allow your deployment identity to upload objects and the Lambda execution role to read the policy. This prerequisite bucket is separate from the CloudTrail log bucket created by the stack.

3. Build and upload code and policy. Replace every placeholder with your own values:

   ```powershell
   $artifactBucket = 'REPLACE-WITH-YOUR-ARTIFACT-BUCKET'
   $demoVpc = 'vpc-REPLACE'
   $notificationEmail = 'REPLACE-WITH-YOUR-EMAIL'
   $stackName = 'acc-security'

   .\.venv\Scripts\python.exe scripts\build.py
   $codeKey = (Get-Content output\build-manifest.json -Raw | ConvertFrom-Json).code_key
   aws s3 cp output\lambda.zip "s3://$artifactBucket/$codeKey" --profile acc-ia --region ap-southeast-2
   aws s3 cp config\policies.json "s3://$artifactBucket/policies/current.json" --content-type application/json --profile acc-ia --region ap-southeast-2
   ```

4. Create the stack in its initial safe state:

   ```powershell
   aws cloudformation deploy --template-file infra\template.json --stack-name $stackName --capabilities CAPABILITY_NAMED_IAM --parameter-overrides "VpcId=$demoVpc" "ArtifactBucket=$artifactBucket" "CodeKey=$codeKey" "NotificationEmail=$notificationEmail" DryRun=true ChangeMonitoringState=DISABLED ScheduleState=DISABLED --profile acc-ia --region ap-southeast-2
   ```

   The stack creates two monitored groups and one unmonitored control group, Lambda and its scoped role, CloudWatch logs, an encrypted SNS topic and email subscription, a single-Region CloudTrail trail with private storage, EventBridge wiring, and Scheduler with its invocation role. The groups are initially unattached with no demo ingress.

5. Confirm the SNS subscription from your inbox. In the stack's Outputs, open MonitorFunction in Lambda and invoke it with `{"trigger":"manual"}`. Inspect the response and CloudWatch logs. With no violating ingress, zero findings is expected. Add a deliberate test violation and verify dry-run behavior before enabling removal.

6. Update the same stack with the same parameters, changing `DryRun=false` and `ChangeMonitoringState=ENABLED` after scope and dry-run verification. Set `ScheduleState=ENABLED` for hourly checks, or leave it disabled until the scheduled rehearsal segment. ScanRate defaults to `rate(1 hour)`. Use the unattached demonstration groups.

## Configure and run the optional live rehearsal

For the submission recording, the prepared presentation contains the demonstration screenshots and is narrated by three presenters. **Live AWS interaction is not required while presenting it.** The report, slide deck and recording are delivered separately from this source repository. The helpers below reproduce tests or collect new evidence.

Helpers discover resource IDs from CloudFormation Outputs. Defaults are stack `acc-security`, Region Sydney and profile `acc-ia`. For another stack name, create the `deployment` directory and a local file `deployment/private-runtime.json`:

```json
{"stack": "YOUR-STACK-NAME"}
```

This file is gitignored and contains no credentials. `scripts/demo.py` also accepts `--stack` and `--profile`. `scripts/lab.py` accepts `--profile` before its subcommand and reads its stack name from this file. Private configuration from the original deployment is not required.

Once remediation is enabled and the email subscription is confirmed:

```powershell
.\demo.ps1 check
.\demo.ps1 prepare
.\demo.ps1 ssh
.\demo.ps1 alert
.\demo.ps1 policy
.\demo.ps1 scheduled
```

| Step | Expected behavior |
|---|---|
| `check` | Read-only health checks; requires active Lambda, remediation enabled, logging trail, confirmed email and unattached groups |
| `prepare` | Restore v1, clear test ingress, add restricted SSH and HTTPS references, enable events and pause Scheduler |
| `ssh` | Create public SSH; verify actual event-triggered removal |
| `alert` | Create public MySQL; verify alert-only and rule retention |
| `policy` | Upload v2; manually evaluate; verify MySQL removal and unchanged code hash |
| `scheduled` | Isolate and verify an actual scheduled correction |
| `scope`, `extended` | Optional control-scope, IPv6 and range checks |
| `rehearse` | Full sequence, then restore prepared baseline with Scheduler paused |
| `finish` | Clear test ingress, restore v1, enable event monitoring and hourly scans |

Run `ssh`, `alert`, `policy` and `scheduled` in order. The policy step needs the rule retained by the alert step. These commands change real AWS configuration and may send incident emails. Rehearsal records are saved under ignored `evidence/`.

Individual controls:

```powershell
.\.venv\Scripts\python.exe scripts\lab.py --help
.\.venv\Scripts\python.exe scripts\lab.py status
.\.venv\Scripts\python.exe scripts\lab.py scan
```

See the [live runbook](docs/RECORDING-RUNBOOK.md) for evidence views and operational details. Its live-screen narration is an alternative reproduction workflow, rather than the current slide-only recording plan. Use your own stack's Outputs instead of the original private console links mentioned in that guide.

## Safety and limitations

- Evaluation is restricted to explicitly listed, tagged groups. Removal additionally requires no attached network interfaces; scope and current rule contents are checked again before revocation.
- Public-anywhere matching recognizes individual normalized `0.0.0.0/0` and `::/0` rules. Combined CIDR coverage, prefix lists, referenced groups, routing and NACL analysis are outside scope.
- Port-range overlap counts as a match. A violating range is removed whole, rather than split into permitted fragments.
- If overlapping policies request both alert and remediation, alert wins and a conflict flag is recorded.
- Invalid policies stop evaluation and fail the invocation. Dry-run reports intended remediation without removing rules.
- Event delivery may be delayed or missed; scheduled checks provide another evaluation opportunity. Repeated evaluations can repeat alerts. There is no durable incident database or exactly-once guarantee.
- Rechecks reduce concurrency risk but do not make separate EC2 API calls atomic.
- `remediated_verified` means the rule was absent after revocation; it does not prove end-to-end network isolation or absence of intrusion.
- SNS publication and inbox delivery are separate. Email requires a confirmed subscription; the original experiments include received-email evidence.

## Costs, pausing and cleanup

Deployment uses billable AWS services. Check AWS Settings > Billing and applicable project credits or spend limits. No present credit balance or zero-cost guarantee is implied. Lambda uses 256 MB with a 90-second timeout; CloudWatch logs retain 14 days; the CloudTrail bucket has lifecycle expiration rules.

Pause automatic evaluation:

```powershell
.\.venv\Scripts\python.exe scripts\lab.py events disable
.\.venv\Scripts\python.exe scripts\lab.py schedule disable
```

This pauses the two evaluation triggers; the stack, CloudTrail and stored data remain. `finish` restores automation rather than tearing down resources. `lab.py clear-demo` removes **all inbound rules** from the three unattached stack-owned demonstration groups, including reference rules.

When no longer needed, review and delete your own CloudFormation stack. The CloudTrail bucket and CloudWatch log group have Retain policies. The separately created artifact bucket is outside the stack. Review retained buckets, object versions, logs and charges separately before deleting them. Do not delete the existing prerequisite VPC.

## Submission and evidence

This repository contains implementation, infrastructure, tests and reproduction instructions. Raw audit evidence, private deployment settings, credentials and student details are excluded. The report and presentation use genuine screenshots. The report pins implementation snapshot `eebce79b2d61b1304b31fb220080ca7c4fc912e9`; later documentation updates do not change that tested source snapshot.

The three-person recording and submission form are separate deliverables. Publishing this repository does not itself accept or submit a GitHub Classroom assignment; that requires the instructor's assignment link.

## AWS references

- [CloudTrail events through EventBridge](https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-service-event-cloudtrail.html)
- [Security group rules](https://docs.aws.amazon.com/vpc/latest/userguide/security-group-rules.html)
- [RevokeSecurityGroupIngress API](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_RevokeSecurityGroupIngress.html)
- [EventBridge Scheduler](https://docs.aws.amazon.com/scheduler/latest/UserGuide/what-is-scheduler.html)
