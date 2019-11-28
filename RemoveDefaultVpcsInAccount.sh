#!/usr/bin/env bash
set -x

aws ec2 describe-regions --profile storm | jq -r '.Regions[].RegionName' | sort -r | xargs -I{} python RemoveDefaultVpc.py --account ${1} --region {}