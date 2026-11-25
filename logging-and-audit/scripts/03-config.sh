#!/usr/bin/env bash
# AWS Config: record all resource types and deliver history to its own bucket.
source "$(dirname "$0")/00-env.sh"

make_bucket "$CONFIG_BUCKET"
aws s3api put-bucket-policy --bucket "$CONFIG_BUCKET" --policy "{
  \"Version\":\"2012-10-17\",
  \"Statement\":[
    {\"Sid\":\"AWSConfigBucketPermissionsCheck\",\"Effect\":\"Allow\",
     \"Principal\":{\"Service\":\"config.amazonaws.com\"},
     \"Action\":\"s3:GetBucketAcl\",\"Resource\":\"arn:aws:s3:::${CONFIG_BUCKET}\",
     \"Condition\":{\"StringEquals\":{\"AWS:SourceAccount\":\"${ACCOUNT_ID}\"}}},
    {\"Sid\":\"AWSConfigBucketExistenceCheck\",\"Effect\":\"Allow\",
     \"Principal\":{\"Service\":\"config.amazonaws.com\"},
     \"Action\":\"s3:ListBucket\",\"Resource\":\"arn:aws:s3:::${CONFIG_BUCKET}\",
     \"Condition\":{\"StringEquals\":{\"AWS:SourceAccount\":\"${ACCOUNT_ID}\"}}},
    {\"Sid\":\"AWSConfigBucketDelivery\",\"Effect\":\"Allow\",
     \"Principal\":{\"Service\":\"config.amazonaws.com\"},
     \"Action\":\"s3:PutObject\",\"Resource\":\"arn:aws:s3:::${CONFIG_BUCKET}/AWSLogs/${ACCOUNT_ID}/Config/*\",
     \"Condition\":{\"StringEquals\":{\"s3:x-amz-acl\":\"bucket-owner-full-control\",\"AWS:SourceAccount\":\"${ACCOUNT_ID}\"}}}
  ]}"

# The service-linked role is created if it does not exist yet.
aws iam create-service-linked-role --aws-service-name config.amazonaws.com 2>/dev/null || true
ROLE_ARN="arn:aws:iam::${ACCOUNT_ID}:role/aws-service-role/config.amazonaws.com/AWSServiceRoleForConfig"

aws configservice put-configuration-recorder --region "$REGION" \
  --configuration-recorder "name=default,roleARN=${ROLE_ARN}" \
  --recording-group "allSupported=true,includeGlobalResourceTypes=true"
aws configservice put-delivery-channel --region "$REGION" \
  --delivery-channel "name=default,s3BucketName=${CONFIG_BUCKET}"
aws configservice start-configuration-recorder --region "$REGION" --configuration-recorder-name default
echo "Config recorder is on, delivering to ${CONFIG_BUCKET}."
