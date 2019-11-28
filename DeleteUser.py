#!/usr/bin/env python

import boto3, json, argparse

from botocore.exceptions import ProfileNotFound, ClientError

parser = argparse.ArgumentParser(description="Delete user with specific resource ARN")
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

	response = boto3.client('sts').assume_role(RoleArn=arn, RoleSessionName="DeleteUser")
	session  = boto3.Session(
		aws_access_key_id	  = response['Credentials']['AccessKeyId'],
		aws_secret_access_key = response['Credentials']['SecretAccessKey'],
		aws_session_token	  = response['Credentials']['SessionToken'] )
	
	return session

def deleteUserWithArn(Arn=None):
	userArnParts = Arn.split(":",5)
	userName  = userArnParts[5].split("/",1)[1]
	accountId = userArnParts[4]

	session = getSessionWithAssumeRole(AccountId=accountId, RoleName=pargs.assume_role)

	client = session.client('iam')
	try:
		userResponse = client.get_user(UserName=userName)
	except:
		print("[{}] user={} not found".format(accountId, userName))
		return

	print("[{}] deleting user={}...".format(accountId, userName))

	''' Delete User Login Profile '''
	userLoginProfile = None
	try:
		res = client.get_login_profile(UserName=userName)
	except ClientError as e:
		if e.response['Error']['Code'] == 'NoSuchEntity':
			userLoginProfile = None
		else:
			raise e
	else:
		userLoginProfile = res['LoginProfile']

	if userLoginProfile:
		print("[{}]   deleting user={} login profile...".format(accountId, userName))
		client.delete_login_profile(UserName=userName)

	''' Delete User Access Keys '''
	pager = client.get_paginator('list_access_keys')
	pages = pager.paginate(**{"UserName": userName})

	for page in pages:
		for accessKeyMetadata in page['AccessKeyMetadata']:
			accessKeyId = accessKeyMetadata['AccessKeyId']
			print("[{}]   deleting accessKey={} from user={}...".format(
				accountId, accessKeyId, userName,
			))
			client.delete_access_key(UserName=userName, AccessKeyId=accessKeyId)

	''' Deactivate & Delete User MFA Devices '''
	pager = client.get_paginator('list_mfa_devices')
	pages = pager.paginate(**{"UserName": userName})

	for page in pages:
		for mfaDevice in page['MFADevices']:
			serialNumber = mfaDevice['SerialNumber']
			print("[{}]   deactivating mfaDevice={} from user={}...".format(
				accountId, serialNumber, userName,
			))
			client.deactivate_mfa_device(UserName=userName, SerialNumber=serialNumber)

			''' Hardware MFA devices may raise exception? '''
			print("[{}]   deleting mfaDevice={} from user={}...".format(
				accountId, serialNumber, userName,
			))
			client.delete_virtual_mfa_device(SerialNumber=serialNumber)

	''' Remove User from Groups '''
	pager = client.get_paginator('list_groups_for_user')
	pages = pager.paginate(**{"UserName": userName})
	
	for page in pages:
		for group in page['Groups']:
			print("[{}]   removing user={} from group={}".format(
				accountId, userName, group['GroupName'],
			))
			client.remove_user_from_group(UserName=userName, GroupName=group['GroupName'])

	''' Delete User Inline Policies '''
	pager = client.get_paginator('list_user_policies')
	pages = pager.paginate(**{"UserName": userName})

	for page in pages:
		for policyName in page['PolicyNames']:
			print("[{}]   deleting policy={} from user={}".format(
				accountId, policyName, userName,
			))
			client.delete_user_policy(UserName=userName, PolicyName=policyName)


	''' Detach User Attached Policies '''
	pager = client.get_paginator('list_attached_user_policies')
	pages = pager.paginate(**{"UserName": userName})

	for page in pages:
		for policy in page['AttachedPolicies']:
			print("[{}]   detaching policy={} from user={}".format(
				accountId, policy['PolicyName'], userName,
			))
			client.detach_user_policy(UserName=userName, PolicyArn=policy['PolicyArn'])

	''' Delete User SSH Public Keys '''
	pager = client.get_paginator('list_ssh_public_keys')
	pages = pager.paginate(**{"UserName": userName})

	for page in pages:
		for sshPublicKey in page['SSHPublicKeys']:
			sshPublicKeyId = sshPublicKey['SSHPublicKeyId']
			print("[{}]   deleting sshPublicKey={} from user={}".format(
				accountId, sshPublicKeyId, userName,
			))
			client.delete_ssh_public_key(UserName=userName, SSHPublicKeyId=sshPublicKeyId)

	''' Delete User Service Specific Credentials '''
	res = client.list_service_specific_credentials(UserName=userName)

	for credential in res['ServiceSpecificCredentials']:
		credentialId = credential['ServiceSpecificCredentialId']
		print("[{}]   deleting credential={} from user={}".format(
			accountId, credentialId, userName,
		))
		client.delete_service_specific_credential(
			UserName=userName, ServiceSpecificCredentialId=credentialId,
		)

	''' Delete User Signing Certificates '''
	pager = client.get_paginator('list_signing_certificates')
	pages = pager.paginate(**{"UserName": userName})

	for page in pages:
		for certificate in page['Certificates']:
			certificateId = certificate['CertificateId']
			print("[{}]   deleting certificate={} from user={}".format(
				accountId, certificateId, userName,
			))
			client.delete_signing_certificate(
				UserName=userName, CertificateId=certificateId,
			)

	''' Delete User '''
	client.delete_user(UserName=userName)
	print("[{}] user={} deleted".format(accountId, userName))

if __name__ == '__main__':
	deleteUserWithArn(Arn=pargs.arn)


