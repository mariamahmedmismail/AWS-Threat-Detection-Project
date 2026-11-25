#!/usr/bin/env bash
# VPC Flow Logs: all traffic on the default VPC, 10-minute aggregation, delivered to S3.
source "$(dirname "$0")/00-env.sh"

VPC_ID="$(aws ec2 describe-vpcs --region "$REGION" --filters Name=is-default,Values=true \
  --query 'Vpcs[0].VpcId' --output text)"
echo "Using VPC ${VPC_ID}"
aws ec2 create-tags --region "$REGION" --resources "$VPC_ID" --tags Key=Name,Value=main-vpc

make_bucket "$FLOW_BUCKET"
aws s3api put-bucket-policy --bucket "$FLOW_BUCKET" --policy "{
  \"Version\":\"2012-10-17\",
  \"Statement\":[
    {\"Sid\":\"AWSLogDeliveryWrite\",\"Effect\":\"Allow\",
     \"Principal\":{\"Service\":\"delivery.logs.amazonaws.com\"},
     \"Action\":\"s3:PutObject\",\"Resource\":\"arn:aws:s3:::${FLOW_BUCKET}/AWSLogs/${ACCOUNT_ID}/*\",
     \"Condition\":{\"StringEquals\":{\"s3:x-amz-acl\":\"bucket-owner-full-control\",\"aws:SourceAccount\":\"${ACCOUNT_ID}\"},
                    \"ArnLike\":{\"aws:SourceArn\":\"arn:aws:logs:${REGION}:${ACCOUNT_ID}:*\"}}},
    {\"Sid\":\"AWSLogDeliveryAclCheck\",\"Effect\":\"Allow\",
     \"Principal\":{\"Service\":\"delivery.logs.amazonaws.com\"},
     \"Action\":[\"s3:GetBucketAcl\",\"s3:ListBucket\"],\"Resource\":\"arn:aws:s3:::${FLOW_BUCKET}\",
     \"Condition\":{\"StringEquals\":{\"aws:SourceAccount\":\"${ACCOUNT_ID}\"},
                    \"ArnLike\":{\"aws:SourceArn\":\"arn:aws:logs:${REGION}:${ACCOUNT_ID}:*\"}}}
  ]}"

aws ec2 create-flow-logs --region "$REGION" \
  --resource-type VPC --resource-ids "$VPC_ID" --traffic-type ALL \
  --log-destination-type s3 --log-destination "arn:aws:s3:::${FLOW_BUCKET}" \
  --max-aggregation-interval 600 \
  --tag-specifications 'ResourceType=vpc-flow-log,Tags=[{Key=Name,Value=main-vpc-flowlogs}]'
echo "Flow logs are delivering to ${FLOW_BUCKET}."
