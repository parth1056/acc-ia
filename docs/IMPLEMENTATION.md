# Implementation overview

The policy engine evaluates selected EC2 inbound security group rules against external JSON policies in S3. Lambda reads current AWS state and chooses alert-only handling or exact-rule revocation followed by verification. CloudTrail and EventBridge provide the change-event path; Scheduler provides an independent periodic scan. SNS delivers incident notifications and CloudWatch records findings.

## Source layout

- src/policy_engine.py: policy validation, protocol normalization, source matching, port-range overlap and response conflict handling.
- src/handler.py: AWS service calls, resource scope, attachment and exact-rule rechecks, remediation verification, notification and structured logging.
- scripts/build.py and infra/: reproducible Lambda packaging and CloudFormation infrastructure.
- scripts/lab.py, scripts/demo.py and demo.ps1: controlled demonstration and restoration helpers.
- tests/: 17 evaluator tests and 10 handler workflow tests.

## Boundaries

Inbound rules only. Public-anywhere matching recognizes individual 0.0.0.0/0 and ::/0 rules. Demo remediation requires explicitly selected, tagged and unattached groups. Matching range rules are removed whole. Alert takes precedence when overlapping policies disagree. Repeated alerts and delayed events are possible. This prototype does not establish intrusion detection or end-to-end network reachability.

## Reproduce tests

Run python -m unittest discover -s tests -v after installing the requirements. Deployment and live operations require your own authorized AWS project and configuration in ap-southeast-2. See README.md before using the helpers.
