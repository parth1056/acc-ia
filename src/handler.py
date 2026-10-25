"""AWS security-group evaluation workflow for the ACC IA group."""

import datetime
import json
import os
import time
import uuid

import boto3
from botocore.config import Config

from policy_engine import evaluate_rule, validate_policy

CONFIG = Config(retries={"mode": "standard", "total_max_attempts": 3}, connect_timeout=3, read_timeout=10)
CLIENTS = {}


def client(service):
    if service not in CLIENTS:
        CLIENTS[service] = boto3.client(service, config=CONFIG)
    return CLIENTS[service]


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def emit(event, **fields):
    print(json.dumps({"application": "ACC Security Monitor", "event": event, "timestamp": now(), **fields}, default=str))


def load_policy():
    response = client("s3").get_object(Bucket=os.environ["POLICY_BUCKET"], Key=os.environ["POLICY_KEY"])
    with response["Body"] as body:
        document = validate_policy(json.loads(body.read()))
    return document, response.get("VersionId", response.get("ETag"))


def get_group(group_id):
    groups = client("ec2").describe_security_groups(GroupIds=[group_id])["SecurityGroups"]
    return groups[0] if groups else None


def eligible(group):
    return group is not None and any(t["Key"] == "ACC-Monitor" and t["Value"] == "true" for t in group.get("Tags", []))


def rules_for(group_id):
    return [r for page in client("ec2").get_paginator("describe_security_group_rules").paginate(
        Filters=[{"Name": "group-id", "Values": [group_id]}]) for r in page["SecurityGroupRules"]]


def unattached(group_id):
    pages = client("ec2").get_paginator("describe_network_interfaces").paginate(
        Filters=[{"Name": "group-id", "Values": [group_id]}])
    return not any(page["NetworkInterfaces"] for page in pages)


def revoke_if_unchanged(group_id, finding, document, dry_run):
    if dry_run:
        return "dry_run"
    if not eligible(get_group(group_id)) or not unattached(group_id):
        return "scope_changed_or_attached"
    current = next((r for r in rules_for(group_id) if r["SecurityGroupRuleId"] == finding["rule_id"]), None)
    if current is None:
        return "already_resolved"
    current_finding = evaluate_rule(current, document)
    if not current_finding or current_finding["action"] != "remediate":
        return "rule_changed"
    if any(current_finding[key] != finding[key] for key in current_finding):
        return "rule_changed"
    client("ec2").revoke_security_group_ingress(GroupId=group_id, SecurityGroupRuleIds=[finding["rule_id"]])
    for attempt in range(4):
        if not any(r["SecurityGroupRuleId"] == finding["rule_id"] for r in rules_for(group_id)):
            return "remediated_verified"
        if attempt < 3:
            time.sleep(0.5 * (attempt + 1))
    return "verification_failed"


def handler(event, context):
    run_id = getattr(context, "aws_request_id", None) or str(uuid.uuid4())
    start = time.monotonic()
    source = "event" if event.get("detail-type") == "AWS API Call via CloudTrail" else event.get("trigger", "manual")
    summary = {"run_id": run_id, "trigger": source, "started_at": now(), "findings": [], "groups": [], "errors": []}
    try:
        document, object_version = load_policy()
        summary.update(policy_version=document["policy_version"], s3_version=object_version)
        allowed = set(filter(None, os.environ["MONITORED_GROUP_IDS"].split(",")))
        detail = event.get("detail", {})
        if source == "event":
            if detail.get("errorCode"):
                summary["ignored"] = "failed_api_call"
                return summary
            if detail.get("eventSource") != "ec2.amazonaws.com" or detail.get("eventName") not in ("AuthorizeSecurityGroupIngress", "ModifySecurityGroupRules"):
                raise ValueError("Unexpected change event")
            if event.get("region") != os.environ["AWS_REGION"] or event.get("account") != os.environ["PROJECT_ID"]:
                raise ValueError("Event belongs to another project or Region")
            group_id = (detail.get("requestParameters") or {}).get("groupId")
            if not group_id:
                raise ValueError("Change event missing groupId; scheduled scan remains available")
            allowed &= {group_id}
            summary.update(event_id=detail.get("eventID"), event_time=detail.get("eventTime"), actor=(detail.get("userIdentity") or {}).get("arn"))
        dry_run = os.environ.get("DRY_RUN", "true").lower() != "false"
        summary["dry_run"] = dry_run
        for group_id in sorted(allowed):
            if not eligible(get_group(group_id)):
                summary["groups"].append({"group_id": group_id, "status": "skipped_not_tagged"})
                continue
            count = 0
            for rule in rules_for(group_id):
                finding = evaluate_rule(rule, document)
                if finding is None:
                    continue
                count += 1
                finding.update(group_id=group_id, detected_at=now())
                try:
                    finding["outcome"] = "alert_only" if finding["action"] == "alert" else revoke_if_unchanged(group_id, finding, document, dry_run)
                    if finding["outcome"] in ("verification_failed", "scope_changed_or_attached"):
                        summary["errors"].append({"rule_id": finding["rule_id"], "error": finding["outcome"]})
                except Exception as exc:
                    finding.update(outcome="remediation_failed", error=str(exc))
                    summary["errors"].append({"rule_id": finding["rule_id"], "error": str(exc)})
                finding["completed_at"] = now()
                summary["findings"].append(finding)
                emit("finding", run_id=run_id, policy_version=document["policy_version"], **finding)
            summary["groups"].append({"group_id": group_id, "status": "violations" if count else "compliant_with_configured_policies", "violations": count})
        if summary["findings"]:
            try:
                published = client("sns").publish(TopicArn=os.environ["TOPIC_ARN"], Subject="ACC: security policy evaluation", Message=json.dumps(summary, indent=2, default=str))
                summary["notification_message_id"] = published["MessageId"]
                summary["notification_status"] = "published_to_sns"
            except Exception as exc:
                summary["notification_status"] = "failed"
                summary["errors"].append({"notification_error": str(exc)})
    except Exception as exc:
        summary["errors"].append({"evaluation_error": str(exc)})
    summary.update(completed_at=now(), duration_ms=round((time.monotonic()-start)*1000, 2))
    emit("evaluation_summary", **summary)
    if summary["errors"]:
        raise RuntimeError(json.dumps(summary, default=str))
    return summary
