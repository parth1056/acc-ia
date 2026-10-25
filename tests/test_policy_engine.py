import copy
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from policy_engine import PolicyError, evaluate_rule, validate_policy

POLICY = json.loads((Path(__file__).resolve().parents[1]/'config/policies.json').read_text())


def rule(**changes):
    return {'SecurityGroupRuleId':'sgr-test','IpProtocol':'tcp','FromPort':22,'ToPort':22,'CidrIpv4':'0.0.0.0/0','IsEgress':False, **changes}


class EvaluationTests(unittest.TestCase):
    def test_public_ssh(self):
        self.assertEqual(evaluate_rule(rule(), POLICY)['action'], 'remediate')

    def test_database_alert(self):
        self.assertEqual(evaluate_rule(rule(FromPort=3306,ToPort=3306),POLICY)['action'],'alert')

    def test_restricted_source(self):
        self.assertIsNone(evaluate_rule(rule(CidrIpv4='203.0.113.1/32'),POLICY))

    def test_public_https_unmatched(self):
        self.assertIsNone(evaluate_rule(rule(FromPort=443,ToPort=443),POLICY))

    def test_port_range_overlap(self):
        self.assertIsNotNone(evaluate_rule(rule(FromPort=20,ToPort=30),POLICY))

    def test_range_no_overlap(self):
        self.assertIsNone(evaluate_rule(rule(FromPort=23,ToPort=30),POLICY))

    def test_ipv6(self):
        self.assertIsNotNone(evaluate_rule(rule(CidrIpv4=None,CidrIpv6='::/0'),POLICY))

    def test_all_protocol_conflict(self):
        result=evaluate_rule(rule(IpProtocol='-1',FromPort=None,ToPort=None),POLICY)
        self.assertTrue(result['response_conflict'])
        self.assertEqual(result['action'],'alert')

    def test_numeric_protocol(self):
        self.assertIsNotNone(evaluate_rule(rule(IpProtocol='6'),POLICY))

    def test_protocol_mismatch(self):
        self.assertIsNone(evaluate_rule(rule(IpProtocol='udp'),POLICY))

    def test_egress_ignored(self):
        self.assertIsNone(evaluate_rule(rule(IsEgress=True),POLICY))

    def test_group_reference_not_public(self):
        self.assertIsNone(evaluate_rule(rule(CidrIpv4=None,ReferencedGroupInfo={'GroupId':'sg-other'}),POLICY))

    def test_disabled_policy(self):
        doc=copy.deepcopy(POLICY)
        doc['policies'][0]['enabled']=False
        self.assertIsNone(evaluate_rule(rule(),doc))

    def test_configuration_change(self):
        doc=copy.deepcopy(POLICY)
        doc['policies'][1]['action']='remediate'
        self.assertEqual(evaluate_rule(rule(FromPort=3306,ToPort=3306),doc)['action'],'remediate')

    def test_invalid_configs(self):
        for field,value in [('action','delete_group'),('protocol','typo'),('enabled','true'),('port_ranges',[[30,20]]),('port_ranges',[[True,22]])]:
            with self.subTest(field=field,value=value):
                doc=copy.deepcopy(POLICY)
                doc['policies'][0][field]=value
                with self.assertRaises(PolicyError): validate_policy(doc)

    def test_duplicate_ids(self):
        doc=copy.deepcopy(POLICY)
        doc['policies'][1]['id']=doc['policies'][0]['id']
        with self.assertRaises(PolicyError): validate_policy(doc)

    def test_valid_policy(self):
        self.assertEqual(validate_policy(POLICY),POLICY)


if __name__ == '__main__':
    unittest.main()
