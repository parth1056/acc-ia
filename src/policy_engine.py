"""Configurable inbound security-group policy evaluation.

ACC IA security policy evaluator.
This module is independent of AWS clients and can be tested offline.
"""

import ipaddress


class PolicyError(ValueError):
    """Policy configuration is invalid; evaluation must stop without changes."""


PROTOCOLS = {"6": "tcp", "17": "udp", "-1": "all", "tcp": "tcp", "udp": "udp", "all": "all"}


def validate_policy(document):
    if not isinstance(document, dict) or set(document) != {"schema_version", "policy_version", "policies"}:
        raise PolicyError("Expected schema_version, policy_version and policies")
    if type(document["schema_version"]) is not int or document["schema_version"] != 1:
        raise PolicyError("Only schema_version 1 is supported")
    if not isinstance(document["policy_version"], str) or not document["policy_version"].strip():
        raise PolicyError("policy_version must be a nonempty string")
    if not isinstance(document["policies"], list) or not document["policies"]:
        raise PolicyError("At least one policy is required")
    ids = set()
    required = {"id", "enabled", "protocol", "port_ranges", "source_match", "action"}
    for policy in document["policies"]:
        if not isinstance(policy, dict) or set(policy) != required:
            raise PolicyError("Each policy must contain exactly the documented fields")
        pid = policy["id"]
        if not isinstance(pid, str) or not pid.strip() or pid in ids:
            raise PolicyError("Policy IDs must be nonempty and unique")
        ids.add(pid)
        if type(policy["enabled"]) is not bool:
            raise PolicyError(f"{pid}: enabled must be boolean")
        if policy["protocol"] not in ("tcp", "udp", "all"):
            raise PolicyError(f"{pid}: supported protocols are tcp, udp and all")
        if policy["source_match"] != "public_anywhere":
            raise PolicyError(f"{pid}: only public_anywhere is supported")
        if policy["action"] not in ("alert", "remediate"):
            raise PolicyError(f"{pid}: action must be alert or remediate")
        ranges = policy["port_ranges"]
        if not isinstance(ranges, list) or not ranges:
            raise PolicyError(f"{pid}: port_ranges must be a nonempty list")
        for pair in ranges:
            if not isinstance(pair, list) or len(pair) != 2 or any(type(n) is not int for n in pair):
                raise PolicyError(f"{pid}: each range must be [integer, integer]")
            if not 0 <= pair[0] <= pair[1] <= 65535:
                raise PolicyError(f"{pid}: invalid port range")
        if policy["protocol"] == "all" and ranges != [[0, 65535]]:
            raise PolicyError(f"{pid}: all-protocol policy must use [[0,65535]]")
    return document


def is_public_anywhere(rule):
    for key in ("CidrIpv4", "CidrIpv6"):
        if rule.get(key):
            network = ipaddress.ip_network(rule[key], strict=False)
            return network.prefixlen == 0
    return False


def matches(rule, policy):
    if rule.get("IsEgress", False) or not policy["enabled"] or not is_public_anywhere(rule):
        return False
    protocol = PROTOCOLS.get(str(rule.get("IpProtocol")))
    if policy["protocol"] == "all":
        return True
    if protocol not in (policy["protocol"], "all"):
        return False
    if protocol == "all":
        return True
    start, end = rule.get("FromPort"), rule.get("ToPort")
    if type(start) is not int or type(end) is not int:
        raise ValueError("TCP/UDP rule missing port bounds")
    return any(start <= high and low <= end for low, high in policy["port_ranges"])


def evaluate_rule(rule, document):
    matched = [p for p in document["policies"] if matches(rule, p)]
    if not matched:
        return None
    actions = {p["action"] for p in matched}
    return {
        "rule_id": rule["SecurityGroupRuleId"],
        "policy_ids": [p["id"] for p in matched],
        "action": "alert" if "alert" in actions else "remediate",
        "response_conflict": len(actions) > 1,
        "protocol": rule["IpProtocol"],
        "from_port": rule.get("FromPort"),
        "to_port": rule.get("ToPort"),
        "source": rule.get("CidrIpv4") or rule.get("CidrIpv6"),
    }
