"""Prepare, rehearse and operate the real AWS demonstration without changing Lambda code."""

import argparse
import datetime as dt
import json
from pathlib import Path
import sys
import time
from urllib.parse import quote

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from policy_engine import validate_policy

REGION = 'ap-southeast-2'
PRIVATE = ROOT / 'deployment/private-runtime.json'


def utc():
    return dt.datetime.now(dt.timezone.utc).isoformat()


class Demo:
    def __init__(self, profile, stack):
        self.session = boto3.Session(profile_name=profile, region_name=REGION)
        self.clients = {}
        self.stack = stack
        self.started = utc()
        self.directory = ROOT / 'evidence' / ('rehearsal-' + dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'))
        self.directory.mkdir(parents=True)
        response = self.api('cloudformation').describe_stacks(StackName=stack)['Stacks'][0]
        self.outputs = {o['OutputKey']: o['OutputValue'] for o in response['Outputs']}
        self.configuration = self.api('lambda').get_function_configuration(FunctionName=self.outputs['MonitorFunction'])
        self.variables = self.configuration['Environment']['Variables']
        self.log_group = '/aws/lambda/' + self.outputs['MonitorFunction']

    def api(self, service):
        if service not in self.clients:
            self.clients[service] = self.session.client(service, config=Config(retries={'mode':'standard','total_max_attempts':3}, connect_timeout=5, read_timeout=30))
        return self.clients[service]

    def record(self, name, value):
        (self.directory / (name + '.json')).write_text(json.dumps(value, indent=2, default=str), encoding='utf-8')
        print('\n' + name.upper() + ' - verified', flush=True)
        evaluation = value.get('evaluation', value)
        if 'trigger' in evaluation:
            print('Trigger:',evaluation['trigger'],'| Policy:',evaluation.get('policy_version'),'| Run:',evaluation.get('run_id'),flush=True)
            for finding in evaluation.get('findings',[]):
                print('  '+','.join(finding['policy_ids'])+' | '+str(finding['protocol'])+' '+str(finding.get('from_port'))+'-'+str(finding.get('to_port'))+' | '+str(finding.get('source'))+' | '+finding['outcome'],flush=True)
        if name == 'health':
            print('Lambda active; trail logging; confirmed email subscription; test groups unattached.',flush=True)
            print('Plan:',value['plan_type'],'| Remaining credit:',value['remaining_credits'],flush=True)
        elif name == 'ready':
            print('Policy v1; automatic change monitoring ON; schedule paused until its demo segment.',flush=True)
            print('Restricted SSH and HTTPS are present. No matching violations.',flush=True)
        elif name == 'policy':
            print('Code SHA before:',value['code_sha256_before'],flush=True)
            print('Code SHA after: ',value['code_sha256_after'],flush=True)
            print('Code unchanged:',value['code_unchanged'],flush=True)
        elif name == 'scope':
            print('Unmonitored control rule retained; test rule then cleared.',flush=True)
        elif name == 'extended':
            print('IPv6 and port-range event tests passed.',flush=True)
        elif name == 'rehearsal-summary':
            print('Passed:',', '.join(value['passed']),'; safe rules preserved.',flush=True)
        elif name == 'finished':
            print('Test ingress cleared; policy v1; change monitoring ON; hourly scanning ON.',flush=True)
        return value

    def rules(self, key):
        return [r for page in self.api('ec2').get_paginator('describe_security_group_rules').paginate(Filters=[{'Name':'group-id','Values':[self.outputs[key]]}]) for r in page['SecurityGroupRules'] if not r['IsEgress']]

    def assert_scope(self):
        for key in ('MonitorGroupA','MonitorGroupB','ControlGroup'):
            gid = self.outputs[key]
            group = self.api('ec2').describe_security_groups(GroupIds=[gid])['SecurityGroups'][0]
            tags = {t['Key']:t['Value'] for t in group.get('Tags',[])}
            if tags.get('aws:cloudformation:stack-name') != self.stack:
                raise RuntimeError('Resource is not owned by this demonstration stack')
            if key != 'ControlGroup' and tags.get('ACC-Monitor') != 'true':
                raise RuntimeError('Monitoring tag missing on ' + key)
            if any(p['NetworkInterfaces'] for p in self.api('ec2').get_paginator('describe_network_interfaces').paginate(Filters=[{'Name':'group-id','Values':[gid]}])):
                raise RuntimeError('Refusing test changes: security group is attached to a workload')

    def check(self):
        self.assert_scope()
        config = self.configuration
        if config.get('State') != 'Active' or config.get('LastUpdateStatus') != 'Successful':
            raise RuntimeError('Lambda is not active and ready')
        if self.variables.get('DRY_RUN') != 'false':
            raise RuntimeError('Remediation is disabled: DRY_RUN is not false')
        rule = self.api('events').describe_rule(Name=self.outputs['ChangeRule'])
        trail = self.api('cloudtrail').get_trail_status(Name=self.stack + '-trail')
        if not trail['IsLogging']:
            raise RuntimeError('CloudTrail is not logging')
        subscriptions = [s for p in self.api('sns').get_paginator('list_subscriptions_by_topic').paginate(TopicArn=self.outputs['IncidentTopic']) for s in p['Subscriptions']]
        confirmed = any(s['Protocol']=='email' and s['SubscriptionArn'] != 'PendingConfirmation' for s in subscriptions)
        if not confirmed:
            raise RuntimeError('No confirmed email subscription')
        response = self.api('s3').get_object(Bucket=self.variables['POLICY_BUCKET'], Key=self.variables['POLICY_KEY'])
        with response['Body'] as body:
            policy = validate_policy(json.loads(body.read()))
        plan = self.api('freetier').get_account_plan_state()
        self.write_links()
        return self.record('health', {'checked_at':utc(),'lambda_state':config['State'],'code_sha256':config['CodeSha256'],'trail_logging':trail['IsLogging'],'event_rule':rule['State'],'email_subscription_confirmed':confirmed,'policy_version':policy['policy_version'],'plan_type':plan['accountPlanType'],'remaining_credits':plan.get('accountPlanRemainingCredits'),'region':REGION,'groups_unattached':True})

    def write_links(self):
        base = 'https://' + REGION + '.console.aws.amazon.com'
        project = self.configuration['FunctionArn'].split(':')[4]
        rows = [
            ('Monitored resource A',base+'/ec2/home?region='+REGION+'#SecurityGroup:groupId='+self.outputs['MonitorGroupA'],self.outputs['MonitorGroupA']),
            ('Monitored resource B',base+'/ec2/home?region='+REGION+'#SecurityGroup:groupId='+self.outputs['MonitorGroupB'],self.outputs['MonitorGroupB']),
            ('S3 policy object',base+'/s3/object/'+self.variables['POLICY_BUCKET']+'?region='+REGION+'&prefix='+quote(self.variables['POLICY_KEY'],safe=''),self.variables['POLICY_KEY']),
            ('Lambda',base+'/lambda/home?region='+REGION+'#/functions/'+self.outputs['MonitorFunction']+'?tab=code',self.outputs['MonitorFunction']),
            ('CloudWatch logs',base+'/go/view?arn='+quote('arn:aws:logs:'+REGION+':'+project+':log-group:'+self.log_group+':*',safe=''),self.log_group),
            ('Change rule',base+'/events/home?region='+REGION+'#/rules/default/'+self.outputs['ChangeRule'],self.outputs['ChangeRule']),
            ('Scheduler',base+'/scheduler/home?region='+REGION,self.outputs['ComplianceSchedule']),
            ('SNS topic',base+'/sns/v3/home?region='+REGION+'#/topic/'+self.outputs['IncidentTopic'],self.outputs['IncidentTopic']),
            ('CloudTrail',base+'/cloudtrailv2/home?region='+REGION+'#/events',self.stack+'-trail')
        ]
        text='# Private operator links\n\nSelected Region: Sydney (ap-southeast-2). Use the existing signed-in AWS project.\n\n| Screen | Link | Resource to locate |\n|---|---|---|\n'
        text+=''.join('| '+label+' | [Open]('+url+') | `'+resource+'` |\n' for label,url,resource in rows)
        text+='\nThese convenience links have not been browser-verified in this run. If AWS changes a route, use its console search and locate the exact resource shown above.\n\nKeep this file local; it contains deployment identifiers.\n'
        (ROOT/'deployment/private-demo-links.md').write_text(text,encoding='utf-8')

    def events(self, enabled):
        current = self.api('events').describe_rule(Name=self.outputs['ChangeRule'])['State']
        if current == ('ENABLED' if enabled else 'DISABLED'):
            return False
        action = self.api('events').enable_rule if enabled else self.api('events').disable_rule
        action(Name=self.outputs['ChangeRule'])
        return True

    def schedule(self, enabled, rate='rate(1 hour)'):
        api = self.api('scheduler')
        current = api.get_schedule(Name=self.outputs['ComplianceSchedule'])
        api.update_schedule(Name=current['Name'], GroupName=current['GroupName'], ScheduleExpression=rate, FlexibleTimeWindow={'Mode':'OFF'}, State='ENABLED' if enabled else 'DISABLED', Target=current['Target'])

    def policy(self, version):
        document = json.loads((ROOT / 'config/policies.json').read_text())
        if version == 'v2':
            document['policy_version'] = 'demo-v2'
            document['policies'][1]['action'] = 'remediate'
        validate_policy(document)
        response = self.api('s3').put_object(Bucket=self.variables['POLICY_BUCKET'], Key=self.variables['POLICY_KEY'], Body=json.dumps(document, indent=2).encode(), ContentType='application/json')
        return {'policy_version':document['policy_version'],'s3_version':response['VersionId']}

    def add(self, key, scenario):
        self.assert_scope()
        protocol,low,high,source = {'ssh':('tcp',22,22,'0.0.0.0/0'),'database':('tcp',3306,3306,'0.0.0.0/0'),'restricted':('tcp',22,22,'203.0.113.10/32'),'https':('tcp',443,443,'0.0.0.0/0'),'range':('tcp',20,30,'0.0.0.0/0'),'ipv6':('tcp',3389,3389,'::/0')}[scenario]
        permission = {'IpProtocol':protocol,'FromPort':low,'ToPort':high}
        permission['Ipv6Ranges' if ':' in source else 'IpRanges'] = [{'CidrIpv6' if ':' in source else 'CidrIp':source,'Description':'ACC demo: '+scenario}]
        response = self.api('ec2').authorize_security_group_ingress(GroupId=self.outputs[key], IpPermissions=[permission])
        rid = response['SecurityGroupRules'][0]['SecurityGroupRuleId']
        introduced = {'introduced_at':utc(),'resource':key,'rule':response['SecurityGroupRules'][0]}
        (self.directory / ('introduced-'+key+'-'+scenario+'.json')).write_text(json.dumps(introduced,indent=2,default=str),encoding='utf-8')
        print('Added '+protocol.upper()+' '+str(low)+'-'+str(high)+' from '+source+' | Rule ID: '+rid,flush=True)
        return rid

    def cleanup_rules(self):
        self.assert_scope()
        planned = {}
        for key in ('MonitorGroupA','MonitorGroupB','ControlGroup'):
            current = self.rules(key)
            if any(not r.get('Description','').startswith('ACC ') for r in current):
                raise RuntimeError('Unrecognized ingress rule found; review it before preparing the demo')
            planned[key] = [r['SecurityGroupRuleId'] for r in current]
        for key, ids in planned.items():
            if ids:
                self.api('ec2').revoke_security_group_ingress(GroupId=self.outputs[key], SecurityGroupRuleIds=ids)

    def scan(self):
        response = self.api('lambda').invoke(FunctionName=self.outputs['MonitorFunction'],InvocationType='RequestResponse',Payload=json.dumps({'trigger':'manual'}).encode())
        with response['Payload'] as body:
            value = json.loads(body.read())
        if response.get('FunctionError') or value.get('errors'):
            raise RuntimeError(json.dumps(value))
        return value

    def wait(self, rule_id, trigger, start_ms, timeout=120):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            pages = self.api('logs').get_paginator('filter_log_events').paginate(logGroupName=self.log_group, startTime=start_ms, filterPattern='"evaluation_summary"')
            for page in pages:
                for item in page.get('events',[]):
                    try:
                        record = json.loads(item['message'])
                    except ValueError:
                        continue
                    if record.get('trigger') != trigger:
                        continue
                    if any(f['rule_id']==rule_id for f in record.get('findings',[])):
                        if record.get('errors'):
                            raise RuntimeError(json.dumps(record['errors']))
                        return record
            time.sleep(3)
        raise TimeoutError('No matching '+trigger+' result within '+str(timeout)+' seconds. Inspect CloudWatch; do not claim success.')

    def present(self, key, rule_id):
        return any(r['SecurityGroupRuleId']==rule_id for r in self.rules(key))

    def prepare(self):
        self.check()
        self.schedule(False)
        self.cleanup_rules()
        self.policy('v1')
        self.add('MonitorGroupA','restricted')
        self.add('MonitorGroupA','https')
        if self.events(True):
            print('Allowing the enabled EventBridge rule to propagate before recording...',flush=True)
            time.sleep(30)
        baseline = self.scan()
        if baseline['findings']:
            raise RuntimeError('Preparation did not produce a compliant baseline')
        return self.record('ready', {'prepared_at':utc(),'baseline':baseline,'event_rule':'ENABLED','schedule':'DISABLED until scheduled segment','policy_version':'demo-v1','expected_safe_rules':['restricted SSH','HTTPS'],'recording_ready':True})

    def step(self, name):
        start_ms = int(time.time()*1000)
        if name == 'ssh':
            rid = self.add('MonitorGroupA','ssh')
            print('Waiting for the real change-event invocation...', flush=True)
            value = self.wait(rid,'event',start_ms)
            if self.present('MonitorGroupA',rid): raise RuntimeError('SSH rule was not removed')
        elif name == 'alert':
            rid = self.add('MonitorGroupA','database')
            print('Waiting for an event-driven alert-only decision...', flush=True)
            value = self.wait(rid,'event',start_ms)
            matching = next(f for f in value['findings'] if f['rule_id']==rid)
            if matching['outcome']!='alert_only' or not self.present('MonitorGroupA',rid):
                raise RuntimeError('Database rule did not remain in alert-only mode')
        elif name == 'policy':
            before = self.api('lambda').get_function_configuration(FunctionName=self.outputs['MonitorFunction'])['CodeSha256']
            changed = self.policy('v2')
            value = self.scan()
            after = self.api('lambda').get_function_configuration(FunctionName=self.outputs['MonitorFunction'])['CodeSha256']
            if before != after: raise RuntimeError('Code changed during policy-only demonstration')
            if not any(f['from_port']==3306 and f['outcome']=='remediated_verified' for f in value['findings']):
                raise RuntimeError('Database remediation was not observed; run the alert step first')
            if any(r.get('FromPort')==3306 for r in self.rules('MonitorGroupA')):
                raise RuntimeError('Database rule remains')
            value = {'evaluation':value,'policy_change':changed,'code_sha256_before':before,'code_sha256_after':after,'code_unchanged':True}
        elif name == 'scheduled':
            if self.events(False):
                print('Allowing the disabled event rule to propagate before the isolated scheduled test...',flush=True)
                time.sleep(30)
            rid = self.add('MonitorGroupB','ssh')
            try:
                self.schedule(True,'rate(1 minute)')
                print('Waiting for a genuine Scheduler invocation (up to two minutes)...',flush=True)
                value = self.wait(rid,'scheduled',start_ms)
                if self.present('MonitorGroupB',rid): raise RuntimeError('Scheduled remediation did not remove the rule')
            finally:
                self.schedule(False)
                if self.events(True):
                    print('Restoring change-event monitoring and allowing it to propagate...',flush=True)
                    time.sleep(30)
        elif name == 'scope':
            rid = self.add('ControlGroup','ssh')
            try:
                value = self.scan()
                if not self.present('ControlGroup',rid): raise RuntimeError('Unmonitored control was changed')
                value = {'scan':value,'unmonitored_rule_retained':True}
            finally:
                self.api('ec2').revoke_security_group_ingress(GroupId=self.outputs['ControlGroup'], SecurityGroupRuleIds=[rid])
        else:
            value = {}
            for scenario in ('range','ipv6'):
                mark = int(time.time()*1000)
                rid = self.add('MonitorGroupB',scenario)
                value[scenario] = self.wait(rid,'event',mark)
                if self.present('MonitorGroupB',rid): raise RuntimeError(scenario+' rule remained')
        return self.record(name,value)

    def rehearse(self):
        completed = []
        try:
            self.prepare()
            for name in ('ssh','alert','policy','scheduled','scope','extended'):
                self.step(name)
                completed.append(name)
            safe = self.rules('MonitorGroupA')
            if not any(r.get('CidrIpv4')=='203.0.113.10/32' and r.get('FromPort')==22 for r in safe):
                raise RuntimeError('Restricted SSH was not preserved')
            if not any(r.get('FromPort')==443 for r in safe):
                raise RuntimeError('Unmatched HTTPS was not preserved')
            return self.record('rehearsal-summary', {'started_at':self.started,'completed_at':utc(),'passed':completed,'safe_rules_preserved':True,'evidence_directory':str(self.directory)})
        finally:
            self.prepare()

    def finish(self):
        self.events(False)
        self.schedule(False)
        self.cleanup_rules()
        self.policy('v1')
        self.events(True)
        self.schedule(True,'rate(1 hour)')
        return self.record('finished',{'finished_at':utc(),'baseline':self.scan(),'event_rule':'ENABLED','schedule':'ENABLED rate(1 hour)'})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command',choices=['check','prepare','rehearse','step','finish'])
    parser.add_argument('segment',nargs='?',choices=['ssh','alert','policy','scheduled','scope','extended'])
    parser.add_argument('--profile',default='acc-ia')
    parser.add_argument('--stack',default=json.loads(PRIVATE.read_text())['stack'] if PRIVATE.exists() else 'acc-security')
    args = parser.parse_args()
    if args.command=='step' and not args.segment:
        parser.error('step requires a segment')
    try:
        demo = Demo(args.profile,args.stack)
        if args.command=='step': demo.step(args.segment)
        else: getattr(demo,args.command)()
        print('Evidence saved locally under evidence/.',flush=True)
    except (BotoCoreError,ClientError,RuntimeError,ValueError,TimeoutError) as exc:
        print('DEMO CHECK FAILED: '+str(exc),file=sys.stderr)
        return 1
    return 0


if __name__=='__main__':
    sys.exit(main())
