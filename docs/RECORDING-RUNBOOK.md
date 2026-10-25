# Optional live demonstration and evidence-capture runbook

The submission recording now uses a screenshot-based presentation narrated by three presenters.
Live AWS interaction is not required while recording it. This guide preserves the alternative
live demonstration workflow for reproducing tests and collecting fresh evidence.
Start with the repository README for deployment, local stack configuration, and current guidance.
Private console links and local presentation files mentioned below are not distributed in this repository.

**Target: 7:30. Maximum: 8:00.** Use three real voices. One operator can share the AWS screen
throughout. No student names, roll numbers, division or group identifiers are needed on screen.
Do not share AWS passwords or credentials between presenters.

## Understand the story

We deliberately introduce a firewall-configuration violation on an unattached AWS test security
group. Our deployed evaluator reads external policies, detects the violation, and either removes
the rule or publishes an alert. Then we change the policy to change its behavior without changing
code. Finally, a genuine scheduled execution finds a pre-existing violation independently.

The helper commands below operate the existing system and verify results. They do not redeploy
Lambda. The AWS console supplies the visible proof: policy, rule state, logs, schedule and email.

## Before recording

1. Open PowerShell in this project folder. Run `./demo.ps1 check`.
2. If login expired, refresh the existing acc-ia profile and complete the browser login privately.
3. Run `./demo.ps1 prepare` and wait for READY. It loads policy v1, adds restricted SSH and
   HTTPS reference rules, enables change monitoring and pauses scheduling until its demo segment.
4. Verify the selected Region is Sydney, ap-southeast-2. AWS Settings > View all projects >
   Overview > Additional Info > Region also shows the project Region.
5. Open the tabs below and locate a real received incident email in the subscribed inbox.
6. Rehearse all voices once. Keep a readable recording master. Hide unrelated tabs, inbox messages,
   notification popups and personal profile menus. Never record sign-in, passwords or tokens.

## Tabs to prepare

| Tab | View to open | What matters |
|---|---|---|
| Slides | Title, workflow, results | Context and conclusion |
| EC2 resource A | Inbound rules and Tags | ACC-Monitor=true; restricted SSH and HTTPS |
| S3 | policies/current.json; View or downloaded JSON | Version, protected ports, response actions |
| Lambda | Function and code/configuration details | Deployed Python program and code hash |
| CloudWatch | Function log group; Search all log streams | Filter `"evaluation_summary"`; expand matching run ID |
| SNS/inbox | Confirmed subscription and received email | Publication versus actual delivery |
| Scheduler | Compliance schedule | Actual one-minute scan for demonstration |
| EC2 resource B | Inbound rules | Scheduled correction |

Direct URLs and actual resource IDs are in the ignored local file
`deployment/private-demo-links.md`. This file is for the operator, not a public repository.

## Short commands

| Command | Meaning |
|---|---|
| `./demo.ps1 check` | Read-only preflight |
| `./demo.ps1 prepare` | Restore recording baseline before a complete take |
| `./demo.ps1 ssh` | Add public SSH and verify its real event-triggered removal |
| `./demo.ps1 alert` | Add database exposure; verify alert-only and retained rule |
| `./demo.ps1 policy` | Upload policy v2; manually evaluate; prove code hash unchanged |
| `./demo.ps1 scheduled` | Isolate and verify a genuine scheduled correction |
| `./demo.ps1 scope` | Optional: prove unmonitored control is retained |
| `./demo.ps1 extended` | Optional: prove IPv6 and range cases |
| `./demo.ps1 rehearse` | Full automated verification, then restore recording baseline |
| `./demo.ps1 finish` | Clear demo ingress; restore v1, change monitoring and hourly scans |

Run ssh, alert, policy and scheduled in that order. **Do not run prepare between them.**
The policy step needs the database rule deliberately left by the alert step.

## Presenter A: 0:00-2:15

### 0:00-0:35 - Problem

**Show:** Title slide.

**Say:**

> Our project is Policy-Driven Cloud Security Monitoring and Automated Remediation Using AWS.
> Cloud firewall settings can become unsafe after an accidental change. For example, administrative
> access may be opened to the entire internet. Our prototype detects configurations that violate
> defined policies and either corrects the rule or alerts the administrator.

### 0:35-1:15 - Architecture

**Show:** Workflow slide, then the deployed Lambda briefly.

**Say:**

> CloudTrail records a security-group change. EventBridge matches the relevant API operation and
> invokes our Python Lambda function. Lambda loads the latest policies from S3 and evaluates the
> current inbound rules. It uses EC2 APIs for correction, CloudWatch for logs, and SNS for
> notifications. A separate Scheduler trigger periodically runs the same evaluator.

### 1:15-1:45 - Resources and boundaries

**Show:** Resource A's monitoring tag and permitted inbound rules.

**Say:**

> Two test security groups are monitored and a third provides an unmonitored control. They are
> unattached to running workloads. Correction is restricted to explicitly allowed, tagged test
> resources, and the function rechecks that no workload is attached. Restricted SSH and unmatched
> HTTPS provide reference rules that should remain unchanged.

### 1:45-2:15 - Policies and handoff

**Show:** S3 policy JSON. Point at policy_version, port_ranges, source_match and action.

**Say:**

> The policies are configuration, separate from code. Version one remediates public administrative
> access but treats public database access as alert-only. The engine also checks port-range overlap
> and unrestricted IPv4 or IPv6 sources. We will now introduce a violation and observe the response.

## Presenter B: 2:15-4:30

### 2:15-3:30 - Automatic correction

**Do:** Show resource A's baseline. Run `./demo.ps1 ssh`. The helper adds TCP/22 from 0.0.0.0/0
and waits for its genuine change-event execution. Refresh EC2 after it reports verification.

**Say while waiting:**

> This command makes a real security-group change, equivalent to adding the rule in the console.
> Port 22 is SSH, and 0.0.0.0/0 means any IPv4 source. We have not pressed Lambda's Test button:
> this evaluation is triggered by the configuration-change event.

**Show:** The CloudWatch evaluation_summary with the helper's run ID. Highlight trigger=event,
ADMIN-ACCESS, action=remediate, outcome=remediated_verified and errors=[]. Then refresh EC2.

**Say:**

> The log identifies the policy and reports verified remediation. The violating rule is gone,
> while the permitted reference rules remain. The function checks current state before changing
> anything and reads the configuration again afterward to verify the result.

If correction is too fast to catch the violating rule in a refresh, use the successful add result
and matching rule ID in the log. Do not disable remediation to manufacture a before screenshot.

### 3:30-4:30 - Alert-only mode

**Do:** Run `./demo.ps1 alert`. Show the retained TCP/3306 rule, matching log and received email.

**Say:**

> We now introduce public database access. Version one defines this as alert-only. The system
> detects the violation and publishes an SNS notification, but leaves the rule unchanged. This
> demonstrates that detection and correction are separate policy decisions. The incident contains
> the affected resource, matched policy and actual response.

Claim email receipt only if an actual message is visible. Otherwise say SNS accepted publication
and inbox delivery has not yet been shown. Match the message to the incident by time or run ID.

**Handoff:**

> Next we will change the response policy without changing the deployed program.

## Presenter C: 4:30-7:30

### 4:30-5:15 - Configuration changes behavior

**Do:** Run `./demo.ps1 policy`. Refresh S3 to show demo-v2 and the database action=remediate.
Show the equal before/after code hashes in the terminal and the removed database rule in EC2.

**Say:**

> We changed the database action in S3 from alert to remediation. This scan is manually requested
> so we can evaluate the changed policy immediately. The same program now removes the database
> rule. The deployed code hash is unchanged, so no code redeployment was needed. Additional
> policies within our supported schema can be introduced through configuration.

### 5:15-6:50 - Independent periodic check

**Do:** Run `./demo.ps1 scheduled`. It pauses the change-event rule, lets the change settle,
adds a violation to resource B, and enables a one-minute schedule. It waits for a result with
trigger=scheduled and the exact new rule ID. No manual invocation proves this step.
Show the schedule, then the actual scheduled summary and corrected EC2 rule list.

**Say:**

> Periodic scanning is independent of the change-event path. For this test the change-event rule
> is paused, so Scheduler must find the existing violation. We temporarily use a one-minute
> interval. The actual execution reports trigger=scheduled and verifies rule removal. Outside
> demonstration, the normal interval is hourly.

**Explain during waiting:**

> Event delivery can be delayed or missed. Periodic checking gives another opportunity to detect
> configuration drift. These tests concern firewall settings, not proof of an intrusion or complete
> network reachability. Our scope is one AWS project and one Region, with inbound rules only.

This segment may take longer in a particular take. Trim idle waiting transparently, retaining
actual timestamps and a caption such as "waiting for scheduled execution". Alternatively show
the genuine recorded scheduled segment from rehearsal and identify it as recorded evidence.
Never relabel a manual execution as automatic.

### 6:50-7:30 - Results and conclusion

**Show:** Results slide and the test/rehearsal summary.

**Say:**

> The prototype demonstrates external policies, selected-resource monitoring, event-driven and
> periodic evaluation, differentiated responses, verified correction and incident publication.
> Twenty-seven local tests check the policy and workflow logic. Live rehearsals also cover scope
> preservation, IPv6 and ranges. Limits include repeated alerts, full removal of broad violating
> rules, and no complete network-path analysis. AWS offers managed compliance tools; our work
> implements and explains a smaller configurable workflow.

## After recording

Run `./demo.ps1 finish`. It clears demo ingress, restores policy v1, enables the change rule and
returns periodic scanning to hourly. Keep the real logs and readable master recording. For another
take, prepare again and repeat the same ordered segments.

## Recovery card

| Symptom | Action |
|---|---|
| Expired session | Stop recording, refresh AWS login privately, run check |
| Duplicate rule | Previous take was not reset; prepare and restart the sequence |
| No matching event result | Inspect trail, event rule, target permission and CloudWatch; don't substitute a manual Test |
| Rule remains after correction | Compare exact rule ID and outcome; don't claim success |
| Policy step has no database finding | Run alert first; it must leave the database rule present |
| Scheduled result takes longer | Wait for the genuine result; trim idle time transparently |
| Email delay | Distinguish published_to_sns from actual inbox receipt |
| Stale console view | Refresh and match run IDs/rule IDs, not just port numbers |

## Screenshot and submission checklist

Capture: policy v1, monitored tags and baseline, automatic event summary, corrected rules,
alert-only retained database rule, received email, policy v2 with unchanged code hashes,
Scheduler configuration and genuine scheduled execution, and local/rehearsal test results.

The finished video must include all three real voices and stay within 7-8 minutes. The pasted
form mentions both a hosted-link field and a video upload capped at 10 MB; confirm the actual
field before exporting. Keep a readable master. If upload under 10 MB is mandatory, compress a
separate copy and inspect small-text legibility. Verify evaluator access for any hosted link.

Avoid claims of a real attack, every-resource coverage, instant/guaranteed delivery or exactly-once
processing. New resource types need more evaluator code; editing JSON alone is not sufficient.
