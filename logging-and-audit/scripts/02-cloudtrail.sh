#!/usr/bin/env bash
# CloudTrail: multi-region trail with log file validation, delivering to a protected S3 bucket.
source "$(dirname "$0")/00-env.sh"

make_bucket "$TRAIL_BUCKET"

# Allow CloudTrail to write to the bucket (only this trail, only this account).
TRAIL_ARN="arn:aws:cloudtrail:${REGION}:${ACCOUNT_ID}:trail/${TRAIL_NAME}"
aws s3api put-bucket-policy --bucket "$TRAIL_BUCKET" --policy "{
  \"Version\":\"2012-10-17\",
  \"Statement\":[
    {\"Sid\":\"AWSCloudTrailAclCheck\",\"Effect\":\"Allow\",
     \"Principal\":{\"Service\":\"cloudtrail.amazonaws.com\"},
     \"Action\":\"s3:GetBucketAcl\",\"Resource\":\"arn:aws:s3:::${TRAIL_BUCKET}\",
     \"Condition\":{\"StringEquals\":{\"aws:SourceArn\":\"${TRAIL_ARN}\"}}},
    {\"Sid\":\"AWSCloudTrailWrite\",\"Effect\":\"Allow\",
     \"Principal\":{\"Service\":\"cloudtrail.amazonaws.com\"},
     \"Action\":\"s3:PutObject\",\"Resource\":\"arn:aws:s3:::${TRAIL_BUCKET}/AWSLogs/${ACCOUNT_ID}/*\",
     \"Condition\":{\"StringEquals\":{\"s3:x-amz-acl\":\"bucket-owner-full-control\",\"aws:SourceArn\":\"${TRAIL_ARN}\"}}}
  ]}"

# Log protection: versioning, and a 90-day retention rule.
aws s3api put-bucket-versioning --bucket "$TRAIL_BUCKET" \
  --versioning-configuration Status=Enabled
aws s3api put-bucket-lifecycle-configuration --bucket "$TRAIL_BUCKET" \
  --lifecycle-configuration '{"Rules":[{
    "ID":"keep-for-90-days","Status":"Enabled","Filter":{},
    "Expiration":{"Days":90},
    "NoncurrentVersionExpiration":{"NoncurrentDays":1},
    "AbortIncompleteMultipartUpload":{"DaysAfterInitiation":1}}]}'

aws cloudtrail create-trail --region "$REGION" --name "$TRAIL_NAME" \
  --s3-bucket-name "$TRAIL_BUCKET" \
  --is-multi-region-trail --enable-log-file-validation
aws cloudtrail put-event-selectors --region "$REGION" --trail-name "$TRAIL_NAME" \
  --event-selectors '[{"ReadWriteType":"All","IncludeManagementEvents":true}]'
aws cloudtrail start-logging --region "$REGION" --name "$TRAIL_NAME"
echo "Trail ${TRAIL_NAME} is logging to ${TRAIL_BUCKET}."
