"""Repeatable ACC demonstration operations. Uses the owner's AWS CLI login profile."""

import argparse
import json
from pathlib import Path

import boto3
from botocore.config import Config

ROOT=Path(__file__).resolve().parents[1]
REGION='ap-southeast-2'
STACK='acc-security'
PRIVATE=ROOT/'deployment/private-runtime.json'
if PRIVATE.exists():
    STACK=json.loads(PRIVATE.read_text())['stack']
CONFIG=Config(retries={'mode':'standard','total_max_attempts':3})


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--profile',default='acc-ia')
    sub=parser.add_subparsers(dest='command',required=True)
    sub.add_parser('status')
    sub.add_parser('scan')
    policy=sub.add_parser('policy')
    policy.add_argument('version',choices=['v1','v2'])
    add=sub.add_parser('add')
    add.add_argument('scenario',choices=['ssh','database','range','ipv6','restricted','https','udp','all'])
    add.add_argument('--group',choices=['a','b','control'],default='a')
    events=sub.add_parser('events')
    events.add_argument('state',choices=['enable','disable'])
    schedule=sub.add_parser('schedule')
    schedule.add_argument('state',choices=['enable','disable'])
    schedule.add_argument('--rate',default='rate(1 hour)',choices=['rate(1 minute)','rate(1 hour)'])
    sub.add_parser('clear-demo',help='Remove ingress only from the three unattached stack-owned demonstration groups')
    args=parser.parse_args()
    session=boto3.Session(profile_name=args.profile,region_name=REGION)
    cfn=session.client('cloudformation',config=CONFIG)
    ec2=session.client('ec2',config=CONFIG)
    lam=session.client('lambda',config=CONFIG)
    stack=cfn.describe_stacks(StackName=STACK)['Stacks'][0]
    outputs={o['OutputKey']:o['OutputValue'] for o in stack['Outputs']}
    def rules(gid):
        return [r for page in ec2.get_paginator('describe_security_group_rules').paginate(Filters=[{'Name':'group-id','Values':[gid]}]) for r in page['SecurityGroupRules']]
    def ensure_unattached(gid):
        group=ec2.describe_security_groups(GroupIds=[gid])['SecurityGroups'][0]
        if not any(t['Key']=='aws:cloudformation:stack-name' and t['Value']==STACK for t in group.get('Tags',[])):
            raise ValueError('Group is not owned by the demonstration stack')
        if any(p['NetworkInterfaces'] for p in ec2.get_paginator('describe_network_interfaces').paginate(Filters=[{'Name':'group-id','Values':[gid]}])):
            raise ValueError('Refusing to modify a group attached to a workload')
    if args.command=='status':
        result={'stack':stack['StackStatus'],'region':REGION,'groups':{name:rules(outputs[name]) for name in ['MonitorGroupA','MonitorGroupB','ControlGroup']},'lambda_code_sha256':lam.get_function_configuration(FunctionName=outputs['MonitorFunction'])['CodeSha256']}
    elif args.command=='scan':
        response=lam.invoke(FunctionName=outputs['MonitorFunction'],InvocationType='RequestResponse',Payload=json.dumps({'trigger':'manual'}).encode())
        with response['Payload'] as body: result=json.loads(body.read())
        if response.get('FunctionError'): raise RuntimeError(json.dumps(result))
    elif args.command=='policy':
        document=json.loads((ROOT/'config/policies.json').read_text())
        if args.version=='v2':
            document['policy_version']='demo-v2'
            document['policies'][1]['action']='remediate'
        config=lam.get_function_configuration(FunctionName=outputs['MonitorFunction'])
        response=session.client('s3',config=CONFIG).put_object(Bucket=config['Environment']['Variables']['POLICY_BUCKET'],Key='policies/current.json',Body=json.dumps(document,indent=2).encode(),ContentType='application/json')
        result={'policy':document,'s3_version':response['VersionId'],'lambda_code_sha256':config['CodeSha256']}
    elif args.command=='add':
        gid=outputs[{'a':'MonitorGroupA','b':'MonitorGroupB','control':'ControlGroup'}[args.group]]
        ensure_unattached(gid)
        ports={'ssh':(22,22),'database':(3306,3306),'range':(20,30),'ipv6':(3389,3389),'restricted':(22,22),'https':(443,443),'udp':(53,53)}
        permission={'IpProtocol':'-1' if args.scenario=='all' else 'udp' if args.scenario=='udp' else 'tcp'}
        if args.scenario!='all': permission.update(FromPort=ports[args.scenario][0],ToPort=ports[args.scenario][1])
        if args.scenario=='ipv6':
            permission['Ipv6Ranges']=[{'CidrIpv6':'::/0','Description':'ACC demo: '+args.scenario}]
        else:
            permission['IpRanges']=[{'CidrIp':'203.0.113.10/32' if args.scenario=='restricted' else '0.0.0.0/0','Description':'ACC demo: '+args.scenario}]
        result=ec2.authorize_security_group_ingress(GroupId=gid,IpPermissions=[permission])
    elif args.command=='events':
        api=session.client('events',config=CONFIG)
        method=api.enable_rule if args.state=='enable' else api.disable_rule
        method(Name=outputs['ChangeRule'])
        result={'event_rule':args.state}
    elif args.command=='schedule':
        api=session.client('scheduler',config=CONFIG)
        current=api.get_schedule(Name=outputs['ComplianceSchedule'])
        api.update_schedule(Name=current['Name'],GroupName=current['GroupName'],ScheduleExpression=args.rate,FlexibleTimeWindow={'Mode':'OFF'},State='ENABLED' if args.state=='enable' else 'DISABLED',Target=current['Target'])
        result={'schedule':args.state,'rate':args.rate}
    else:
        result={}
        for name in ['MonitorGroupA','MonitorGroupB','ControlGroup']:
            gid=outputs[name]
            ensure_unattached(gid)
            ids=[r['SecurityGroupRuleId'] for r in rules(gid) if not r['IsEgress']]
            if ids: ec2.revoke_security_group_ingress(GroupId=gid,SecurityGroupRuleIds=ids)
            result[name]={'removed_ingress':ids}
    print(json.dumps(result,indent=2,default=str))


if __name__=='__main__':
    main()
