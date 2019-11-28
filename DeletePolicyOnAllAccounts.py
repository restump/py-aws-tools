#!/usr/bin/env python

import boto3
import pprint
import argparse
import csv

from multiprocessing import Process
from botocore.exceptions import ProfileNotFound, ClientError

parser = argparse.ArgumentParser(description="Parallel, multi-account execution")
parser.add_argument('--policy', 
	type=str )
parser.add_argument('--assume_role', 
	type=str,
	default="CloudCoreAdmin" )
parser.add_argument('--organization_owner_id', 
	type=str, help="Organization OwnerId", 
	default="730529347585" )
pargs  = parser.parse_args()

def getSessionWithAssumeRole(OwnerId=None,RoleName=None):
	arn = "arn:aws:iam::{0}:role/{1}".format(OwnerId,RoleName)

	response = boto3.client('sts').assume_role(RoleArn=arn, RoleSessionName="mySession")
	session  = boto3.Session(
		aws_access_key_id	  = response['Credentials']['AccessKeyId'],
		aws_secret_access_key = response['Credentials']['SecretAccessKey'],
		aws_session_token	  = response['Credentials']['SessionToken'] )
	
	return session

def getAccountList(OwnerId=None,RoleName=None):
	session  = getSessionWithAssumeRole(OwnerId=OwnerId,RoleName=RoleName)
	accounts = []
	response = session.client('organizations').list_accounts()
	
	while True:
		for item in response['Accounts']:
			if item['Status'] == 'ACTIVE':
				accounts.append(item['Id'])

		if 'NextToken' not in response:
			break
		response = session.client('organizations').list_accounts(NextToken=response['NextToken'])
	return accounts

def getItemsWithMaxItems(Session=None,MethodName=None,ClientName=None,ItemListKey=None,**kwargs):
	function = getattr(Session.client(ClientName), MethodName)
	
	items = []
	response = function(**kwargs)
	while True:
		for item in response[ItemListKey]:
			items.append(item)

		if response['IsTruncated'] == False:
			break
		response = function(Marker=response['Marker'],**kwargs)
	return items

def delete_policy(Session=None,OwnerId=None,PolicyName=None):

	policyArn = "arn:aws:iam::{}:policy/{}".format(OwnerId, PolicyName)
	try:
		response = Session.client('iam').get_policy(PolicyArn=policyArn)
	except:
		print("[{1}] policy {0} not found".format(PolicyName, OwnerId))
		return

	Session.client('iam').delete_policy(PolicyArn=policyArn)

def test_role(Session=None,OwnerId=None,RoleName=None):
	try:
		response = Session.client('iam').get_role(RoleName=RoleName)
	except:
		print("[{1}] role {0} not accessible".format(RoleName, OwnerId))
		return

if __name__ == '__main__':
	accounts = getAccountList(OwnerId=pargs.organization_owner_id,RoleName=pargs.assume_role)

	procs = []
	for account in accounts:
		session = getSessionWithAssumeRole(OwnerId=account,RoleName=pargs.assume_role)
		
		proc = Process(target=delete_policy, args=(session, account, pargs.policy,))
		procs.append(proc)
		proc.start()
	
	for proc in procs:
		proc.join()
