# Week 1: Logging and Audit

**Owner:** Ganna | **Pair and reviewer:** Menna | **Region:** `eu-north-1` (Europe, Stockholm)

This section covers the logging foundation of the project. It records every API call, configuration
change and network flow in the AWS account, stores the evidence safely, and makes it queryable with
Athena. The other weeks build on it: GuardDuty reads these logs, and the incident timelines are rebuilt
from them.

## What is built

| Component | Setting | Why |
|---|---|---|
| AWS Budgets | Monthly budget of $25, alerts at 50%, 80% and 100% | Cost control |
| CloudTrail | `main-trail`, multi-region, management events (read and write), log file validation | Who did what, and proof the logs were not changed |
| Trail bucket | Block Public Access, SSE-S3, versioning, 90-day lifecycle rule | Protected, bounded evidence store |
| AWS Config | Recorder on, all resource types, own bucket | What changed, and when |
| VPC Flow Logs | Default VPC (`main-vpc`), all traffic, 10-minute interval, own bucket | Network metadata |
| Athena | Database `cloudtrail_logs`, tables `events` and `vpc_flow_logs`, saved queries Q1 to Q9 | Rebuild timelines with SQL |

The design reasons are in `design/design-01-technology-stack.md` and
`design/design-02-security-system-architecture.md`.

## Requirements

- AWS CLI v2, signed in to the project account with permission to create the resources above.
- Bash (Linux, macOS, or Git Bash and WSL on Windows).
- An email address for the budget alerts.

## Configuration

The settings live in `scripts/00-env.sh`: region, bucket names and the budget limit.
Bucket names must be globally unique, so change `SUFFIX` if a name is taken.

```bash
export SUFFIX="yourtag"
export BUDGET_EMAIL="you@example.com"
```

## Execution

Run the scripts in order from the `week1-logging` folder. Later steps depend on earlier ones.

```bash
bash scripts/01-budget.sh
bash scripts/02-cloudtrail.sh
bash scripts/03-config.sh
bash scripts/04-flow-logs.sh
bash scripts/05-athena.sh
```

| Script | Creates |
|---|---|
| `01-budget.sh` | Monthly budget and the three alerts |
| `02-cloudtrail.sh` | Trail bucket, its policy, versioning and lifecycle rule, then the trail |
| `03-config.sh` | Config bucket and policy, then the recorder and delivery channel |
| `04-flow-logs.sh` | Flow logs bucket and policy, then the flow log on the default VPC |
| `05-athena.sh` | Athena results bucket, database, both tables and the saved queries |

The scripts reflect the environment that was built in the console. They fail if a resource already
exists, so run them in a new or empty account, or skip the steps you already have.

## Verify

1. CloudTrail: open `main-trail` and check that it is logging, multi-region, with log file validation enabled.
2. Wait about 5 minutes, then open the trail bucket and look for files under `AWSLogs/`.
3. Athena: select the database `cloudtrail_logs`, then run

   ```sql
   SELECT eventtime, eventname, useridentity.arn FROM cloudtrail_logs.events ORDER BY eventtime DESC LIMIT 10;
   ```

4. The full list of checks is in `docs/test-plan.md`.

## Athena queries

The saved queries are in `athena/queries/`. Queries Q2, Q4 and Q9 contain `<...>` placeholders that you
fill in before running them.

| Query | Use |
|---|---|
| Q1 | All activity in the last 24 hours |
| Q2 | Everything one user, role or instance did |
| Q3 | Failed or denied calls |
| Q4 | Everything done with one access key |
| Q5 | S3 policy, ACL and Block Public Access changes |
| Q6 | EC2 and security group changes |
| Q7 | IAM and STS changes |
| Q8 | Console sign-ins |
| Q9 | Network traffic for one IP |

CloudTrail times are in UTC. Cairo time is UTC+2, so write incident timelines in UTC.

## Roll back and clean up

- A misconfigured logging service can be deleted and recreated. The buckets and the logs already in them are kept.
- A deleted or overwritten log can be restored from its previous version in the trail bucket.
- To reduce cost, stop the Config recorder or delete the flow log. Budget alerts tell you when to do this.

## Limitations

- The trail is single-account and multi-region, not an organization trail. Joining an AWS Organization
  would upgrade the Free Plan and expire the credits.
- Logs use S3 default encryption (SSE-S3), not a customer-managed KMS key, to save cost.
- S3 data events, CloudTrail Insights, CloudWatch Logs, S3 server access logs and ELB logs are off.
