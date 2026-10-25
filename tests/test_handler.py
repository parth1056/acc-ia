import copy
import io
import json
import os
import sys
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
import handler
from test_policy_engine import POLICY, rule

ENV={'MONITORED_GROUP_IDS':'sg-a,sg-b','DRY_RUN':'false','AWS_REGION':'ap-southeast-2','PROJECT_ID':'123456789012','TOPIC_ARN':'arn:test'}
GROUP={'Tags':[{'Key':'ACC-Monitor','Value':'true'}]}


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.stack=[]
        for target,value in [('load_policy',(copy.deepcopy(POLICY),'v1')),('get_group',GROUP),('unattached',True)]:
            mocker=patch.object(handler,target,return_value=value)
            self.stack.append(mocker)
            mocker.start()
        self.env=patch.dict(os.environ,ENV)
        self.env.start()
        self.api=MagicMock()
        self.api.publish.return_value={'MessageId':'message-test'}
        self.api_patch=patch.object(handler,'client',return_value=self.api)
        self.api_patch.start()

    def tearDown(self):
        self.api_patch.stop()
        self.env.stop()
        for item in self.stack: item.stop()

    def run_handler(self,event=None):
        with redirect_stdout(io.StringIO()):
            return handler.handler(event or {'trigger':'manual'},SimpleNamespace(aws_request_id='run-test'))

    def test_alert_does_not_revoke(self):
        with patch.object(handler,'rules_for',return_value=[rule(FromPort=3306,ToPort=3306)]):
            result=self.run_handler()
        self.assertEqual(result['findings'][0]['outcome'],'alert_only')
        self.api.revoke_security_group_ingress.assert_not_called()

    def test_dry_run(self):
        with patch.dict(os.environ,{'DRY_RUN':'true'}),patch.object(handler,'rules_for',return_value=[rule()]):
            result=self.run_handler()
        self.assertEqual(result['findings'][0]['outcome'],'dry_run')
        self.api.revoke_security_group_ingress.assert_not_called()

    def test_verified_remediation(self):
        with patch.object(handler,'rules_for',side_effect=[[rule()],[rule()],[],[]]):
            result=self.run_handler()
        self.assertEqual(result['findings'][0]['outcome'],'remediated_verified')
        self.api.revoke_security_group_ingress.assert_called_once_with(GroupId='sg-a',SecurityGroupRuleIds=['sgr-test'])

    def test_attached_group_is_not_changed(self):
        with patch.object(handler,'rules_for',return_value=[rule()]),patch.object(handler,'unattached',return_value=False):
            with self.assertRaises(RuntimeError): self.run_handler()
        self.api.revoke_security_group_ingress.assert_not_called()

    def test_invalid_policy_stops_resource_reads(self):
        with patch.object(handler,'load_policy',side_effect=ValueError('invalid policy')),patch.object(handler,'rules_for') as read:
            with self.assertRaises(RuntimeError): self.run_handler()
        read.assert_not_called()

    def test_unmonitored_event_is_ignored(self):
        event={'detail-type':'AWS API Call via CloudTrail','region':'ap-southeast-2','account':'123456789012','detail':{'eventSource':'ec2.amazonaws.com','eventName':'AuthorizeSecurityGroupIngress','requestParameters':{'groupId':'sg-control'}}}
        with patch.object(handler,'rules_for') as read:
            result=self.run_handler(event)
        self.assertEqual(result['groups'],[])
        read.assert_not_called()

    def test_wrong_region_rejected(self):
        event={'detail-type':'AWS API Call via CloudTrail','region':'us-east-1','account':'123456789012','detail':{'eventSource':'ec2.amazonaws.com','eventName':'AuthorizeSecurityGroupIngress','requestParameters':{'groupId':'sg-a'}}}
        with self.assertRaises(RuntimeError): self.run_handler(event)

    def test_notification_failure_is_reported(self):
        self.api.publish.side_effect=RuntimeError('SNS permission denied')
        with patch.object(handler,'rules_for',return_value=[rule(FromPort=3306,ToPort=3306)]):
            with self.assertRaisesRegex(RuntimeError,'notification_error'): self.run_handler()

    def test_changed_rule_not_removed(self):
        finding={'group_id':'sg-a',**handler.evaluate_rule(rule(),POLICY)}
        with patch.object(handler,'rules_for',return_value=[rule(FromPort=443,ToPort=443)]):
            status=handler.revoke_if_unchanged('sg-a',finding,POLICY,False)
        self.assertEqual(status,'rule_changed')
        self.api.revoke_security_group_ingress.assert_not_called()

    def test_tag_removed(self):
        with patch.object(handler,'get_group',return_value={'Tags':[]}),patch.object(handler,'rules_for') as read:
            result=self.run_handler()
        self.assertEqual(result['groups'][0]['status'],'skipped_not_tagged')
        read.assert_not_called()


if __name__=='__main__':
    unittest.main()
