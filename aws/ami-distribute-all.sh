#!/bin/sh

set -e


if [ "$#" != "2" ]; then
    echo "Usage: $0 <source ami id> <source aws region>"
    exit 1
fi

ami_id="$1"
ami_region="$2"

regions=$(aws ec2 describe-regions | jq -r '.Regions[] | .RegionName')

for region in $regions; do
    ./ami-copy.sh "$ami_id" "$ami_region" "$region" &
    pids[${i}]=$!
done

# wait for all pids
for pid in ${pids[*]}; do
    wait $pid
done
