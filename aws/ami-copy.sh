#!/bin/bash

set -e

if [ "$#" != "3" ]; then
    echo "Usage: $0 <source ami id> <source aws region> <destination aws region>"
    exit 1
fi

ami_id="$1"
src_region="$2"
dst_region="$3"
ami_owner="003398142640"

# get the ami name in source
name=$(aws --region "$src_region" \
    ec2 describe-images \
    --owner $ami_owner \
    --image-ids $ami_id \
    | jq -r '.Images | sort_by(.CreationDate) | last(.[]).Name')

# check if ami exist in destination
dst_ami_id=$(aws --region "$dst_region" \
    ec2 describe-images \
    --owner $ami_owner \
    --filters "Name=name,Values=${name}" \
    | jq -r '.Images | sort_by(.CreationDate) | last(.[]).ImageId')

if [ "$dst_ami_id" != "null" ]; then
    echo "AMI exists in $dst_region with id: ${dst_ami_id}"

    aws --region eu-west-1 ssm put-parameter \
        --name global_frontloader_ami_${dst_region} \
        --value "$dst_ami_id" --type String --overwrite
    exit 0
fi

dst_ami_id=$(aws --region "$dst_region" \
   ec2 copy-image \
   --source-image-id $ami_id \
   --source-region $src_region \
   --name "$name" \
   | jq -r .ImageId)

echo "Waiting for $dst_region ami: $dst_ami_id"

while true; do
    state=$(aws --region "$dst_region" \
                ec2 describe-images \
                --owner $ami_owner \
                --image-ids $dst_ami_id \
            | jq -r '.Images | sort_by(.CreationDate) | last(.[]).State')
    if [ "$state" = "available" ]; then
        break
    fi
    sleep 3
done

echo "Ready $dst_region ami: $dst_ami_id"

aws --region eu-west-1 ssm put-parameter \
    --name global_frontloader_ami_${dst_region} \
    --value "$dst_ami_id" --type String --overwrite
