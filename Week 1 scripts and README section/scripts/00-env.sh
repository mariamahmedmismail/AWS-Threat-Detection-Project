#!/usr/bin/env bash
# Shared settings and helpers. Sourced by the other scripts, do not run directly.
set -euo pipefail

export REGION="eu-north-1"
export ACCOUNT_ID="$(aws sts get-caller-identity --query Account --output text)"
export SUFFIX="${SUFFIX:-mmmgh}"   # keeps bucket names globally unique

export TRAIL_NAME="main-trail"
export TRAIL_BUCKET="main-trail-s3-bucket-${SUFFIX}"
export CONFIG_BUCKET="our-aws-config-bucket-${SUFFIX}"
export FLOW_BUCKET="vpcflowlogs-s3bucket-${SUFFIX}"
export ATHENA_BUCKET="athena-query-results-${SUFFIX}"

# Required for the budget alerts: export BUDGET_EMAIL=you@example.com
export BUDGET_EMAIL="${BUDGET_EMAIL:-}"
export BUDGET_LIMIT_USD="25"

# Creates a private, encrypted bucket: Block Public Access on, SSE-S3 default encryption.
make_bucket() {
  local bucket="$1"
  aws s3api create-bucket --bucket "$bucket" --region "$REGION" \
    --create-bucket-configuration "LocationConstraint=${REGION}"
  aws s3api put-public-access-block --bucket "$bucket" \
    --public-access-block-configuration \
    "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
  aws s3api put-bucket-encryption --bucket "$bucket" \
    --server-side-encryption-configuration \
    '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}'
}
