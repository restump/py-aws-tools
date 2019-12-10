#!/usr/bin/env python

import boto3, json, argparse

from botocore.exceptions import ProfileNotFound, ClientError

parser = argparse.ArgumentParser(description="Delete role with specific resource ARN")
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

def getSessionWithAssumeRole(AccountId=None, RoleName=None):
	arn = "arn:aws:iam::{0}:role/{1}".format(AccountId,RoleName)

	response = boto3.client('sts').assume_role(RoleArn=arn, RoleSessionName="DeleteRole")
	session  = boto3.Session(
		aws_access_key_id	  = response['Credentials']['AccessKeyId'],
		aws_secret_access_key = response['Credentials']['SecretAccessKey'],
		aws_session_token	  = response['Credentials']['SessionToken'] )
	
	return session

def deleteRoleWithArn(Arn=None):
	roleArnParts = Arn.split(":",5)
	roleName  = roleArnParts[5].split("/",1)[1]
	accountId = roleArnParts[4]

	session = getSessionWithAssumeRole(AccountId=accountId, RoleName=pargs.assume_role)

	client = session.client('iam')
	try:
		roleResponse = client.get_role(RoleName=roleName)
	except:
		print("[{}] role={} not found".format(accountId, roleName))
		return

	print("[{}] deleting role={}...".format(accountId, roleName))

	''' Delete Role Inline Policies '''
	pager = client.get_paginator('list_role_policies')
	pages = pager.paginate(**{"RoleName": roleName})

	for page in pages:
		for policyName in page['PolicyNames']:
			print("[{}]   deleting policy={} from role={}".format(
				accountId, policyName, roleName,
			))
			client.delete_role_policy(RoleName=roleName, PolicyName=policyName)

	''' Detach Role Attached Policies '''
	pager = client.get_paginator('list_attached_role_policies')
	pages = pager.paginate(**{"RoleName": roleName})

	for page in pages:
		for policy in page['AttachedPolicies']:
			print("[{}]   detaching policy={} from role={}".format(
				accountId, policy['PolicyName'], roleName,
			))
			client.detach_role_policy(RoleName=roleName, PolicyArn=policy['PolicyArn'])

	''' Delete Role '''
	client.delete_role(RoleName=roleName)
	print("[{}] role={} deleted".format(accountId, roleName))

if __name__ == '__main__':
	deleteRoleWithArn(Arn=pargs.arn)


