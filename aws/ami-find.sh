#!/bin/bash

set -e

if [ "$#" != "2" ]; then
    echo "Usage: $0 <aws profile> <aws region>"
    exit 1
fi

aws_profile="$1"
aws_region="$2"
ami_owner="003398142640"

ami_id=$(aws --profile "$aws_profile" \
             --region "$aws_region" \
             ec2 describe-images \
             --owner $ami_owner \
             --filters "Name=name,Values=frontloader*" \
             | jq -r '.Images | sort_by(.CreationDate) | last(.[]).ImageId'
      )

# no extra output since this is used from deploy-region.sh
echo $ami_id
