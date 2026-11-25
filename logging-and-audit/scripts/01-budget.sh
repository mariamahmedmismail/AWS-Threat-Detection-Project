#!/usr/bin/env bash
# AWS Budgets: monthly budget with alerts at 50%, 80% and 100%.
source "$(dirname "$0")/00-env.sh"
: "${BUDGET_EMAIL:?Set BUDGET_EMAIL first, for example: export BUDGET_EMAIL=you@example.com}"

BUDGET="{\"BudgetName\":\"monthly-budget\",\"BudgetLimit\":{\"Amount\":\"${BUDGET_LIMIT_USD}\",\"Unit\":\"USD\"},\"TimeUnit\":\"MONTHLY\",\"BudgetType\":\"COST\"}"

alert() {
  printf '{"Notification":{"NotificationType":"ACTUAL","ComparisonOperator":"GREATER_THAN","Threshold":%s,"ThresholdType":"PERCENTAGE"},"Subscribers":[{"SubscriptionType":"EMAIL","Address":"%s"}]}' "$1" "$BUDGET_EMAIL"
}
NOTIFICATIONS="[$(alert 50),$(alert 80),$(alert 100)]"

aws budgets create-budget --region us-east-1 --account-id "$ACCOUNT_ID" \
  --budget "$BUDGET" --notifications-with-subscribers "$NOTIFICATIONS"
echo "Budget created. Confirm the subscription email that AWS sends."
