#!/usr/bin/env python

import boto3, json, argparse

from botocore.exceptions import ProfileNotFound, ClientError

parser = argparse.ArgumentParser(description="Delete policy with specific resource ARN")
parser.add_argument(
	'--arn', 
	type=str,
)
parser.add_argument(
	'--assume_role', 
	type=str,
	default="CloudCoreAdmin",
)
pargs = parser.parse_args()

def getSessionWithAssumeRole(AccountId=None, policyName=None):
	arn = "arn:aws:iam::{0}:role/{1}".format(AccountId,policyName)

	response = boto3.client('sts').assume_role(RoleArn=arn, RoleSessionName="DeleteRole")
	session  = boto3.Session(
		aws_access_key_id	  = response['Credentials']['AccessKeyId'],
		aws_secret_access_key = response['Credentials']['SecretAccessKey'],
		aws_session_token	  = response['Credentials']['SessionToken'] )
	
	return session

def deletePolicyWithArn(Arn=None):
	policyArnParts 	= Arn.split(":",5)
	policyName  	= policyArnParts[5].split("/",1)[1]
	accountId 		= policyArnParts[4]

	if accountId == 'aws':
		print("[{}] policy={} is a managed policy and cannot be deleted".format("AmazonPolicy", policyArn))
		return

	session = getSessionWithAssumeRole(AccountId=accountId, policyName=pargs.assume_role)
	client  = session.client('iam')
	try:
		policyResponse = client.get_policy(PolicyArn=Arn)
	except:
		print("[{}] policy={} not found".format(accountId, policyName))
		return

	if policyResponse['Policy']['AttachmentCount'] > 0:
		print("[{}] policy={} has {} attachments and cannot be deleted".format(accountId, policyName))
	
	print("[{}] deleting policy={}...".format(accountId, policyName))

	''' Delete Policy Versions '''
	pager = client.get_paginator('list_policy_versions')
	pages = pager.paginate(**{"PolicyArn": Arn})

	for page in pages:
		for version in page['Versions']:
			if version['IsDefaultVersion'] == False:
				print("[{}]   deleting version={} from policy={}".format(
					accountId, version['VersionId'], policyName,
				))
				client.delete_policy_version(PolicyArn=Arn, VersionId=version['VersionId'])

	''' Delete Policy '''
	client.delete_policy(PolicyArn=Arn)
	print("[{}] policy={} deleted".format(accountId, policyName))

if __name__ == '__main__':
	deletePolicyWithArn(Arn=pargs.arn)


