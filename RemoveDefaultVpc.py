#!/usr/bin/env python

import boto3, argparse, sys, time

parser = argparse.ArgumentParser(description="Remove default VPC in specified account and region")
parser.add_argument('--account', 
  type=str )
parser.add_argument('--region', 
  type=str )
parser.add_argument('--role', 
  type=str,
  default="CloudCoreEng" )
pargs = parser.parse_args()

def getItemsWithMaxResults(Session=None,MethodName=None,ClientName=None,
  ItemListKey=None,RegionName=None,**kwargs):
  function = getattr(Session.client(ClientName, region_name=RegionName), MethodName)
  
  items = []
  response = function(**kwargs)
  while True:
    for item in response[ItemListKey]:
        items.append(item)

    if 'NextToken' not in response:
      break
    response = function(NextToken=response['NextToken'],**kwargs)
  return items

def getSessionWithAssumeRole(OwnerId=None,RoleName=None,RoleSessionName="mySession"):
  arn = "arn:aws:iam::{0}:role/{1}".format(OwnerId,RoleName)

  response = boto3.client('sts').assume_role(RoleArn=arn, RoleSessionName=RoleSessionName)
  session  = boto3.Session(
    aws_access_key_id     = response['Credentials']['AccessKeyId'],
    aws_secret_access_key = response['Credentials']['SecretAccessKey'],
    aws_session_token     = response['Credentials']['SessionToken'] )
  
  return session

if __name__ == '__main__':
  session = getSessionWithAssumeRole(OwnerId=pargs.account,RoleName=pargs.role,RoleSessionName="DeleteDefaultVPCs")
  client  = session.client('ec2', region_name=pargs.region)

  response = client.describe_vpcs(Filters=[{'Name': 'isDefault', 'Values': ['true']}])

  vpc = None
  if response and 'Vpcs' in response:
    for item in response.get('Vpcs',[]):
      vpc = item

  if not vpc:
    print("no default vpcs returned by describe-vpcs in account={} and region={}".format(pargs.account,pargs.region))
    sys.exit(1)

  vpcId = vpc['VpcId']
  dhcpOptionsId = vpc.get('DhcpOptionsId',None)

  ''' Safety check: ENIs in the VPC -- skip '''
  networkInterfaces = getItemsWithMaxResults(Session=session,MethodName='describe_network_interfaces',
    ClientName='ec2',ItemListKey='NetworkInterfaces',RegionName=pargs.region,
    **{'Filters': [{'Name': 'vpc-id', 'Values': [vpcId]}]} )
  if networkInterfaces:
    print("default vpc with id={} has {} network interfaces...skipped".format(vpcId,len(networkInterfaces)))
    sys.exit(1)

  print("Removing default VPC with id={} in region={}".format(vpcId,pargs.region))
  ''' Delete SecurityGroups '''
  securityGroups = getItemsWithMaxResults(Session=session,MethodName='describe_security_groups',
    ClientName='ec2',ItemListKey='SecurityGroups',RegionName=pargs.region,
    **{'Filters': [{'Name': 'vpc-id', 'Values': [vpcId]}]} )
  for group in securityGroups:
    groupName = group.get('GroupName',None)
    if not groupName == 'default':
      groupId = group.get('GroupId')
      print(" - removing security group with id={} and name={}...".format(groupId, groupName))
      client.delete_security_group(GroupId=groupId)

  ''' Delete subnets '''
  subnets = getItemsWithMaxResults(Session=session,MethodName='describe_subnets',
    ClientName='ec2',ItemListKey='Subnets',RegionName=pargs.region,
    **{'Filters': [{'Name': 'vpc-id', 'Values': [vpcId]}]} )
  for subnet in subnets:
    subnetId = subnet['SubnetId']
    print(" - deleting subnet with id={}".format(subnetId))
    client.delete_subnet(SubnetId=subnetId)

  ''' Detach and delete Internet Gateway (igw) '''
  internetGateways = getItemsWithMaxResults(Session=session,MethodName='describe_internet_gateways',
    ClientName='ec2',ItemListKey='InternetGateways',RegionName=pargs.region,
    **{'Filters': [{'Name': 'attachment.vpc-id', 'Values': [vpcId]}]} )
  for igw in internetGateways:
    internetGatewayId = igw['InternetGatewayId']
    print(" - detaching internet gateway with id={}...".format(internetGatewayId))
    client.detach_internet_gateway(VpcId=vpcId, InternetGatewayId=internetGatewayId)
    print(" -  deleting internet gateway with id={}...".format(internetGatewayId))
    client.delete_internet_gateway(InternetGatewayId=internetGatewayId)

  ''' Detach VPN Gateway (vgw) '''
  vpnGateways = getItemsWithMaxResults(Session=session,MethodName='describe_vpn_gateways',
    ClientName='ec2',ItemListKey='VpnGateways',RegionName=pargs.region,
    **{'Filters': [{'Name': 'attachment.vpc-id', 'Values': [vpcId]}]} )
  for vgw in vpnGateways:
    vpnGatewayId = vgw['VpnGatewayId']
    print(" - detaching vpn gateway with id={}...".format(vpnGatewayId))
    client.detach_vpn_gateway(VpcId=vpcId, VpnGatewayId=vpnGatewayId)

  ''' Delete default VPC '''
  print(" - deleting default VPC with id={}".format(vpcId))
  client.delete_vpc(VpcId=vpcId)

  ''' Delete DhcpOptions; some timing issues -- sleep '''
  if dhcpOptionsId:
    time.sleep(2)
    print(" - deleting DhcpOption set with id={}".format(dhcpOptionsId))
    client.delete_dhcp_options(DhcpOptionsId=dhcpOptionsId)

