"""Build the Lambda package and reproducible CloudFormation deployment template."""

import json
import hashlib
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def ref(name):
    return {"Ref": name}


def sub(value):
    return {"Fn::Sub": value}


def arn(name):
    return {"Fn::GetAtt": [name, "Arn"]}


def main():
    output = ROOT / 'output'
    output.mkdir(exist_ok=True)
    with zipfile.ZipFile(output/'lambda.zip','w',zipfile.ZIP_DEFLATED) as archive:
        for path in sorted((ROOT/'src').glob('*.py')):
            archive.write(path,path.name)
    code_key='artifacts/lambda-'+hashlib.sha256((output/'lambda.zip').read_bytes()).hexdigest()[:16]+'.zip'
    (output/'build-manifest.json').write_text(json.dumps({'code_key':code_key},indent=2))
    resources = {}
    def add(name, kind, properties, why, must=None, **extra):
        resources[name] = {'Type':kind,'Properties':properties,'Metadata':{'com.aws.cloudformation.Context':{'why':why,'must':must or []}},**extra}
    tags=[{'Key':'Project','Value':'ACC-IA-Cloud-Security'},{'Key':'Owner','Value':'ProjectOwner'}]
    group_names=['MonitorGroupA','MonitorGroupB','ControlGroup']
    for number,name in enumerate(group_names):
        add(name,'AWS::EC2::SecurityGroup',{
            'GroupDescription':'Unattached ACC security policy demonstration group',
            'GroupName':sub('${AWS::StackName}-'+['monitor-a','monitor-b','control'][number]),
            'VpcId':ref('VpcId'),
            'Tags':tags+[{'Key':'ACC-Monitor','Value':'true' if number<2 else 'false'}]},
            'Controlled firewall configuration evaluation', ['Keep unattached to workloads; ingress added only during controlled tests'])
    add('LogBucket','AWS::S3::Bucket',{
        'PublicAccessBlockConfiguration':{k:True for k in ['BlockPublicAcls','BlockPublicPolicy','IgnorePublicAcls','RestrictPublicBuckets']},
        'BucketEncryption':{'ServerSideEncryptionConfiguration':[{'ServerSideEncryptionByDefault':{'SSEAlgorithm':'AES256'}}]},
        'VersioningConfiguration':{'Status':'Enabled'},
        'LifecycleConfiguration':{'Rules':[{'Id':'ExpireLabLogs','Status':'Enabled','ExpirationInDays':30,'NoncurrentVersionExpiration':{'NoncurrentDays':7}}]},'Tags':tags},
        'Private CloudTrail audit storage with bounded retention', ['Retain audit evidence on stack deletion'],DeletionPolicy='Retain',UpdateReplacePolicy='Retain')
    add('LogBucketPolicy','AWS::S3::BucketPolicy',{'Bucket':ref('LogBucket'),'PolicyDocument':{'Version':'2012-10-17','Statement':[
        {'Sid':'TLSOnly','Effect':'Deny','Principal':'*','Action':'s3:*','Resource':[arn('LogBucket'),sub('${LogBucket.Arn}/*')],'Condition':{'Bool':{'aws:SecureTransport':'false'}}},
        {'Sid':'TrailACL','Effect':'Allow','Principal':{'Service':'cloudtrail.amazonaws.com'},'Action':'s3:GetBucketAcl','Resource':arn('LogBucket'),'Condition':{'StringEquals':{'aws:SourceArn':sub('arn:${AWS::Partition}:cloudtrail:${AWS::Region}:${AWS::AccountId}:trail/${AWS::StackName}-trail')}}},
        {'Sid':'TrailWrite','Effect':'Allow','Principal':{'Service':'cloudtrail.amazonaws.com'},'Action':'s3:PutObject','Resource':sub('${LogBucket.Arn}/cloudtrail/AWSLogs/${AWS::AccountId}/*'),'Condition':{'StringEquals':{'s3:x-amz-acl':'bucket-owner-full-control','aws:SourceArn':sub('arn:${AWS::Partition}:cloudtrail:${AWS::Region}:${AWS::AccountId}:trail/${AWS::StackName}-trail')}}}
    ]}},'Allow this trail to deliver audit records; deny insecure transport')
    add('Trail','AWS::CloudTrail::Trail',{'TrailName':sub('${AWS::StackName}-trail'),'S3BucketName':ref('LogBucket'),'S3KeyPrefix':'cloudtrail','IsLogging':True,'IsMultiRegionTrail':False,'IncludeGlobalServiceEvents':False,'EnableLogFileValidation':True,'EventSelectors':[{'ReadWriteType':'WriteOnly','IncludeManagementEvents':True}],'Tags':tags},'Enable management-write event delivery to EventBridge',['Selected Region only; management writes only'],DependsOn='LogBucketPolicy')
    add('IncidentTopic','AWS::SNS::Topic',{'TopicName':sub('${AWS::StackName}-incidents'),'DisplayName':'ACC Security','KmsMasterKeyId':'alias/aws/sns','Tags':tags},'Notify project owner about policy violations')
    add('IncidentEmail','AWS::SNS::Subscription',{'TopicArn':ref('IncidentTopic'),'Protocol':'email','Endpoint':ref('NotificationEmail')},'Deliver alerts to the configured project-owner inbox',['Subscription confirmation required'])
    add('FunctionLogs','AWS::Logs::LogGroup',{'LogGroupName':sub('/aws/lambda/${AWS::StackName}-monitor'),'RetentionInDays':14,'Tags':tags},'Structured execution and remediation evidence',['Retain for report evidence'],DeletionPolicy='Retain',UpdateReplacePolicy='Retain')
    add('ExecutionRole','AWS::IAM::Role',{'RoleName':sub('${AWS::StackName}-lambda-role'),'AssumeRolePolicyDocument':{'Version':'2012-10-17','Statement':[{'Effect':'Allow','Principal':{'Service':'lambda.amazonaws.com'},'Action':'sts:AssumeRole'}]},'Policies':[{'PolicyName':'ScopedSecurityEvaluation','PolicyDocument':{'Version':'2012-10-17','Statement':[
        {'Effect':'Allow','Action':['ec2:DescribeSecurityGroups','ec2:DescribeSecurityGroupRules','ec2:DescribeNetworkInterfaces'],'Resource':'*'},
        {'Effect':'Allow','Action':'ec2:RevokeSecurityGroupIngress','Resource':[sub('arn:${AWS::Partition}:ec2:${AWS::Region}:${AWS::AccountId}:security-group/${MonitorGroupA}'),sub('arn:${AWS::Partition}:ec2:${AWS::Region}:${AWS::AccountId}:security-group/${MonitorGroupB}')],'Condition':{'StringEquals':{'ec2:ResourceTag/ACC-Monitor':'true'}}},
        {'Effect':'Allow','Action':'s3:GetObject','Resource':sub('arn:${AWS::Partition}:s3:::${ArtifactBucket}/policies/current.json')},
        {'Effect':'Allow','Action':'sns:Publish','Resource':ref('IncidentTopic')},
        {'Effect':'Allow','Action':['kms:Decrypt','kms:GenerateDataKey'],'Resource':sub('arn:${AWS::Partition}:kms:${AWS::Region}:${AWS::AccountId}:key/*'),'Condition':{'StringEquals':{'kms:ViaService':sub('sns.${AWS::Region}.amazonaws.com')}}},
        {'Effect':'Allow','Action':['logs:CreateLogStream','logs:PutLogEvents'],'Resource':sub('${FunctionLogs.Arn}')}
    ]}}],'Tags':tags},'Least-privilege Lambda execution',['Read policy object; revoke only two monitored test groups; no workload access'])
    add('MonitorFunction','AWS::Lambda::Function',{'FunctionName':sub('${AWS::StackName}-monitor'),'Runtime':'python3.13','Handler':'handler.handler','Role':arn('ExecutionRole'),'Code':{'S3Bucket':ref('ArtifactBucket'),'S3Key':ref('CodeKey')},'Timeout':90,'MemorySize':256,'Environment':{'Variables':{'POLICY_BUCKET':ref('ArtifactBucket'),'POLICY_KEY':'policies/current.json','TOPIC_ARN':ref('IncidentTopic'),'MONITORED_GROUP_IDS':{'Fn::Join':[',',[ref('MonitorGroupA'),ref('MonitorGroupB')]]},'PROJECT_ID':ref('AWS::AccountId'),'DRY_RUN':'true'}},'Tags':tags},'One reusable policy engine for changes and scheduled scans',['Start in dry-run mode; exact group allowlist plus tag; Python 3.13'],DependsOn='FunctionLogs')
    add('ChangeRule','AWS::Events::Rule',{'Name':sub('${AWS::StackName}-changes'),'State':'DISABLED','EventPattern':{'source':['aws.ec2'],'detail-type':['AWS API Call via CloudTrail'],'detail':{'eventSource':['ec2.amazonaws.com'],'eventName':['AuthorizeSecurityGroupIngress','ModifySecurityGroupRules']}},'Targets':[{'Id':'SecurityMonitor','Arn':arn('MonitorFunction')}]},'Evaluate current rules after ingress additions or modifications',['Enable after dry-run verification; exclude revoke events'])
    add('EventPermission','AWS::Lambda::Permission',{'FunctionName':ref('MonitorFunction'),'Action':'lambda:InvokeFunction','Principal':'events.amazonaws.com','SourceArn':arn('ChangeRule'),'SourceAccount':ref('AWS::AccountId')},'Only this change rule may invoke Lambda')
    add('SchedulerRole','AWS::IAM::Role',{'RoleName':sub('${AWS::StackName}-scheduler-role'),'AssumeRolePolicyDocument':{'Version':'2012-10-17','Statement':[{'Effect':'Allow','Principal':{'Service':'scheduler.amazonaws.com'},'Action':'sts:AssumeRole','Condition':{'StringEquals':{'aws:SourceAccount':ref('AWS::AccountId')},'ArnEquals':{'aws:SourceArn':sub('arn:${AWS::Partition}:scheduler:${AWS::Region}:${AWS::AccountId}:schedule-group/default')}}}]},'Policies':[{'PolicyName':'InvokeMonitorOnly','PolicyDocument':{'Version':'2012-10-17','Statement':[{'Effect':'Allow','Action':'lambda:InvokeFunction','Resource':arn('MonitorFunction')}]}}],'Tags':tags},'Allow scheduled scans to invoke only the monitor')
    add('ComplianceSchedule','AWS::Scheduler::Schedule',{'Name':sub('${AWS::StackName}-compliance'),'ScheduleExpression':'rate(1 hour)','FlexibleTimeWindow':{'Mode':'OFF'},'State':'DISABLED','Target':{'Arn':arn('MonitorFunction'),'RoleArn':arn('SchedulerRole'),'Input':'{"trigger":"scheduled"}','RetryPolicy':{'MaximumEventAgeInSeconds':300,'MaximumRetryAttempts':2}}},'Periodic recovery of missed configuration changes',['Enable only after test; hourly outside demo'])
    resources['MonitorFunction']['Properties']['Environment']['Variables']['DRY_RUN']=ref('DryRun')
    resources['ChangeRule']['Properties']['State']=ref('ChangeMonitoringState')
    resources['ComplianceSchedule']['Properties']['State']=ref('ScheduleState')
    resources['ComplianceSchedule']['Properties']['ScheduleExpression']=ref('ScanRate')
    template={'AWSTemplateFormatVersion':'2010-09-09','Description':'ACC IA security-group compliance prototype: external JSON policies, event-driven evaluation, scheduled checks, verified remediation and alerts.','Metadata':{'AWSToolsMetrics':{'AWSAgentToolkit':'aws-cloudformation@3'}},'Parameters':{'VpcId':{'Type':'AWS::EC2::VPC::Id'},'ArtifactBucket':{'Type':'String'},'CodeKey':{'Type':'String','Default':code_key},'NotificationEmail':{'Type':'String'},'DryRun':{'Type':'String','Default':'true','AllowedValues':['true','false']},'ChangeMonitoringState':{'Type':'String','Default':'DISABLED','AllowedValues':['ENABLED','DISABLED']},'ScheduleState':{'Type':'String','Default':'DISABLED','AllowedValues':['ENABLED','DISABLED']},'ScanRate':{'Type':'String','Default':'rate(1 hour)','AllowedValues':['rate(1 minute)','rate(1 hour)']}},'Resources':resources,'Outputs':{name:{'Value':ref(name)} for name in ['MonitorGroupA','MonitorGroupB','ControlGroup','LogBucket','IncidentTopic','MonitorFunction','ChangeRule','ComplianceSchedule']}}
    (ROOT/'infra').mkdir(exist_ok=True)
    path=ROOT/'infra/template.json'
    path.write_text(json.dumps(template,indent=2)+'\n',encoding='utf-8')
    print(f'Built {path}: {path.stat().st_size} bytes; {len(resources)} resources')
    print(f'Lambda archive: {(output/"lambda.zip").stat().st_size} bytes')


if __name__ == '__main__':
    main()
