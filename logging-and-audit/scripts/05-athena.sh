#!/usr/bin/env bash
# Athena: results bucket, database, the two log tables, and the saved queries Q1 to Q9.
source "$(dirname "$0")/00-env.sh"
HERE="$(cd "$(dirname "$0")/.." && pwd)"

make_bucket "$ATHENA_BUCKET"

# Runs one query and waits until it finishes.
run_sql() {
  local id state
  id="$(aws athena start-query-execution --region "$REGION" --query-string "$1" \
    --result-configuration "OutputLocation=s3://${ATHENA_BUCKET}/" \
    --query QueryExecutionId --output text)"
  while :; do
    state="$(aws athena get-query-execution --region "$REGION" --query-execution-id "$id" \
      --query 'QueryExecution.Status.State' --output text)"
    case "$state" in
      SUCCEEDED) return 0 ;;
      FAILED|CANCELLED) echo "Query ${state}: $1" >&2; return 1 ;;
    esac
    sleep 2
  done
}

# Fills in the placeholders in a .sql file.
render() {
  sed -e "s/__ACCOUNT_ID__/${ACCOUNT_ID}/g" -e "s/__TRAIL_BUCKET__/${TRAIL_BUCKET}/g" \
      -e "s/__FLOW_BUCKET__/${FLOW_BUCKET}/g" -e "s/__REGION__/${REGION}/g" "$1"
}

run_sql "CREATE DATABASE IF NOT EXISTS cloudtrail_logs"
for table in cloudtrail vpc_flow_logs; do
  run_sql "$(render "${HERE}/athena/tables/${table}.sql")"
done

for file in "${HERE}"/athena/queries/*.sql; do
  aws athena create-named-query --region "$REGION" --name "$(basename "$file" .sql)" \
    --database cloudtrail_logs --query-string "$(cat "$file")" >/dev/null
  echo "Saved query $(basename "$file" .sql)"
done
