# Week 4 Automation Core: `ir-dispatcher` Lambda

Automated, evidence-first response to GuardDuty and Security Hub findings for the three Project 4 scenarios
(compromised EC2, exposed access keys, public S3 bucket).

**Owner:** Muhammad Hossam (Member 4) · **Pair:** Member 6 · **Status:** skeleton, dry-run by default

Design: `docs/soar-automation-flow.md` · Contracts: `docs/api-interface-documentation.md` (the code follows section 4 of it)

## Folder layout

```text
lambda/ir_dispatcher/   the function (deploy this folder)
  handler.py            entry point: lambda_handler; processing order, skip rules, result
  normalize.py          GuardDuty / Security Hub event -> one Finding shape
  playbooks.py          which steps run for which resource and trigger
  actions.py            the AWS calls (evidence, containment); nothing deletes
  records.py            action record (S3), Security Hub note, SNS message
  config.py             environment variables; DRY_RUN stays on unless set to "false"
  aws.py                boto3 clients with standard retries
events/                 sample events, one per scenario (for tests and manual invokes)
rules/                  EventBridge rule patterns (same as the API doc)
iam/                    execution-role policy, trust policy, DLQ and target templates
tests/                  39 tests against a mocked AWS account (moto)
run_local.py            run the handler on your laptop against a sample event
```

## Safety switches

| Switch | Default | Effect |
|---|---|---|
| `DRY_RUN` | `true` | Plans and records steps, changes nothing. Live only when set to `false` (case and surrounding spaces ignored). Any other value, or no value, keeps dry-run on. |
| `REQUIRE_SANDBOX_TAG` | `true` | Only resources tagged `env=sandbox` are touched |
| `ALLOW_SAMPLE_FINDINGS` | `false` | GuardDuty sample findings are ignored |
| IAM explicit deny | always | The role can never terminate, delete keys, delete buckets or delete evidence |

## 1. Run the tests (no AWS account needed)

```powershell
cd week4_soar
python -m venv venv
venv\Scripts\activate
pip install -r requirements-dev.txt
python -m pytest -q
```

Expected: `39 passed`.

## 2. Deploy to the sandbox account (AWS CLI v2, PowerShell)

> Deployed and tested on 25 Nov in eu-north-1 (results: API doc section 11). Notes from that run: the team account only allows **eu-north-1** (organization SCP), so first replace `us-east-1` and `123456789012` in `events/*.json` with your region and account; `put-function-concurrency` fails on a new account (limit 10) and can be skipped; outside us-east-1, `create-bucket` needs `--create-bucket-configuration LocationConstraint=<region>`.

**Before deploying:** tag every sandbox resource the Lambda may act on with `env=sandbox`: test instances, the IAM users used in the exposed-keys scenario, the instance **roles** of test instances, and the scenario buckets. Untagged resources are skipped (`out_of_scope`), and the IAM policy only allows changes to tagged users and roles.

**Validate the policy with AWS's own checker** (after step a fills the placeholders):

```powershell
aws accessanalyzer validate-policy --policy-type IDENTITY_POLICY --policy-document file://iam/ir-dispatcher-policy.filled.json
```

Fix any `ERROR` or `SECURITY_WARNING` it reports before continuing.

Set these once per PowerShell window (use your values):

```powershell
$ACCOUNT="123456789012"; $REGION="us-east-1"; $BUCKET="ir-evidence-bucket"; $LOGBUCKET="your-log-bucket"
$VPC="vpc-xxxxxxxx"
```

### a. Fill the placeholders in the IAM and template files

```powershell
Get-ChildItem iam\*.json -Exclude *.filled.json | ForEach-Object {
  (Get-Content $_) -replace 'ACCOUNT_ID',$ACCOUNT -replace 'REGION',$REGION -replace 'EVIDENCE_BUCKET',$BUCKET -replace 'LOG_BUCKET',$LOGBUCKET |
    Set-Content ($_.FullName -replace '\.json$','.filled.json') }
```

### b. Queues, topic, isolation security group

```powershell
aws sqs create-queue --queue-name ir-lambda-dlq
aws sqs create-queue --queue-name ir-eventbridge-dlq
aws sqs set-queue-attributes --queue-url https://sqs.$REGION.amazonaws.com/$ACCOUNT/ir-eventbridge-dlq --attributes file://iam/eventbridge-dlq-queue-policy.filled.json
aws sns create-topic --name ir-alerts          # skip if Member 6 already created it
$SG = aws ec2 create-security-group --group-name ir-isolation --description "IR isolation: no inbound" --vpc-id $VPC --query GroupId --output text
aws ec2 revoke-security-group-egress --group-id $SG --ip-permissions "IpProtocol=-1,IpRanges=[{CidrIp=0.0.0.0/0}]"
```

Then replace `ISOLATION_SG_ID` in `iam\ir-dispatcher-policy.filled.json` with the value of `$SG`.
(SSM forensics through VPC endpoints is decided with Ganna; see API doc section 5.3.)

### c. Role and function

```powershell
aws iam create-role --role-name ir-dispatcher-role --assume-role-policy-document file://iam/lambda-trust-policy.json
aws iam put-role-policy --role-name ir-dispatcher-role --policy-name ir-dispatcher --policy-document file://iam/ir-dispatcher-policy.filled.json

Compress-Archive -Path lambda\ir_dispatcher\*.py -DestinationPath ir-dispatcher.zip -Force

aws lambda create-function --function-name ir-dispatcher --runtime python3.12 --handler handler.lambda_handler `
  --role arn:aws:iam::${ACCOUNT}:role/ir-dispatcher-role --zip-file fileb://ir-dispatcher.zip --timeout 60 --memory-size 256 `
  --environment "Variables={DRY_RUN=true,EVIDENCE_BUCKET=$BUCKET,ISOLATION_SG_ID=$SG,SNS_TOPIC_ARN=arn:aws:sns:${REGION}:${ACCOUNT}:ir-alerts,AUTOMATION_ROLE_ARN=arn:aws:iam::${ACCOUNT}:role/ir-forensics-automation-role}"

aws lambda put-function-concurrency --function-name ir-dispatcher --reserved-concurrent-executions 5
aws lambda put-function-event-invoke-config --function-name ir-dispatcher --maximum-retry-attempts 2 --destination-config file://iam/lambda-destination.filled.json
```

To update the code later: `Compress-Archive ... -Force` again, then
`aws lambda update-function-code --function-name ir-dispatcher --zip-file fileb://ir-dispatcher.zip`.

### c2. Evidence bucket (with Ganna; do this before step c)

Object Lock must be switched on when the bucket is created; it also turns on versioning. GOVERNANCE mode protects evidence from normal deletes but can still be removed by an admin with special permission, which is the right level for a lab (COMPLIANCE mode cannot be undone, even by the root user, until the retention ends).

```powershell
aws s3api create-bucket --bucket $BUCKET --object-lock-enabled-for-bucket       # outside us-east-1 add: --create-bucket-configuration LocationConstraint=$REGION
aws s3api put-object-lock-configuration --bucket $BUCKET --object-lock-configuration "ObjectLockEnabled=Enabled,Rule={DefaultRetention={Mode=GOVERNANCE,Days=30}}"
aws s3api put-public-access-block --bucket $BUCKET --public-access-block-configuration "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
aws s3api put-bucket-policy --bucket $BUCKET --policy file://iam/evidence-bucket-policy.filled.json
```

New buckets are encrypted (SSE-S3) by default. If the team's KMS requirement applies to evidence too, add `put-bucket-encryption` with the team key.

### c3. Forensics runbook and its role

```powershell
aws iam create-role --role-name ir-forensics-automation-role --assume-role-policy-document file://iam/forensics-automation-trust-policy.filled.json
aws iam put-role-policy --role-name ir-forensics-automation-role --policy-name ir-forensics --policy-document file://iam/forensics-automation-policy.filled.json
aws ssm create-document --name IR-CollectEC2Forensics --document-type Automation --document-format YAML --content file://ssm/IR-CollectEC2Forensics.yaml
```

Each sandbox instance's role also needs the AWS managed policy `AmazonSSMManagedInstanceCore` and `iam/sandbox-instance-forensics-upload-policy.filled.json`.

Test the runbook on a **non-isolated** sandbox instance first:

```powershell
aws ssm start-automation-execution --document-name IR-CollectEC2Forensics --parameters "InstanceId=i-xxxxxxxx,EvidenceBucket=$BUCKET,FindingId=manual-test-1,AutomationAssumeRole=arn:aws:iam::${ACCOUNT}:role/ir-forensics-automation-role"
```

### d. Test the function directly (still dry-run)

Put a real sandbox instance ID into a copy of `events/gd-ec2-high.json`, then:

```powershell
aws lambda invoke --function-name ir-dispatcher --cli-binary-format raw-in-base64-out --payload fileb://events/gd-ec2-high.json out.json
Get-Content out.json
```

Expected `"status": "dry_run"` and a record under `s3://<bucket>/actions/`.

### e. EventBridge rules (after the direct test works)

```powershell
foreach ($r in "ir-auto-contain-high","ir-auto-contain-keys","ir-analyst-action") {
  aws events put-rule --name $r --event-pattern file://rules/$r.json
  aws events put-targets --rule $r --targets file://iam/eventbridge-targets.filled.json
  aws lambda add-permission --function-name ir-dispatcher --statement-id "eb-$r" --action lambda:InvokeFunction `
    --principal events.amazonaws.com --source-arn arn:aws:events:${REGION}:${ACCOUNT}:rule/$r
}
```

`ir-notify` (every finding of severity 4 or more) targets the SNS topic and is set up with Member 6.
Before creating `ir-analyst-action`, replace the account ID in `rules/ir-analyst-action.json` with yours and make sure Member 6 has created the two custom actions.

Check a rule matches an event without sending anything:

```powershell
aws events test-event-pattern --event-pattern file://rules/ir-auto-contain-high.json --event file://events/gd-ec2-high.json
```

### e2. Forensics on isolated instances (option b, decide with Ganna)

The isolation group blocks all outbound traffic, so an isolated instance's SSM agent cannot reach SSM. Option (b) lets it reach **only** AWS endpoints inside the VPC:

```powershell
$SUBNET="subnet-xxxxxxxx"; $RTB="rtb-xxxxxxxx"     # the scenario VPC's subnet and route table
$EPSG = aws ec2 create-security-group --group-name ir-endpoints --description "SSM endpoints for isolated instances" --vpc-id $VPC --query GroupId --output text
aws ec2 authorize-security-group-ingress --group-id $EPSG --ip-permissions "IpProtocol=tcp,FromPort=443,ToPort=443,UserIdGroupPairs=[{GroupId=$SG}]"
foreach ($svc in "ssm","ssmmessages","ec2messages") {
  aws ec2 create-vpc-endpoint --vpc-id $VPC --vpc-endpoint-type Interface --service-name com.amazonaws.$REGION.$svc --subnet-ids $SUBNET --security-group-ids $EPSG --private-dns-enabled
}
aws ec2 authorize-security-group-egress --group-id $SG --ip-permissions "IpProtocol=tcp,FromPort=443,ToPort=443,UserIdGroupPairs=[{GroupId=$EPSG}]"
aws ec2 create-vpc-endpoint --vpc-id $VPC --vpc-endpoint-type Gateway --service-name com.amazonaws.$REGION.s3 --route-table-ids $RTB --policy-document file://iam/s3-endpoint-policy.filled.json
$PL = aws ec2 describe-managed-prefix-lists --filters "Name=prefix-list-name,Values=com.amazonaws.$REGION.s3" --query "PrefixLists[0].PrefixListId" --output text
aws ec2 authorize-security-group-egress --group-id $SG --ip-permissions "IpProtocol=tcp,FromPort=443,ToPort=443,PrefixListIds=[{PrefixListId=$PL}]"
```

Trade-offs to state in the report:

- Interface endpoints are billed per hour. Create them for the scenario week and delete them afterwards (`aws ec2 delete-vpc-endpoints`).
- The S3 endpoint policy allows **only** uploads to `forensics/*` in the evidence bucket, so malware on an isolated instance cannot use it to send data to another bucket. But it applies to **every** instance whose route table uses this endpoint, so use it only in the scenario VPC.
- Isolated instances can now reach the SSM endpoints. That is the price of remote forensics; the alternative is option (a), collecting before isolating.

### f. End to end with GuardDuty sample findings

```powershell
aws lambda update-function-configuration --function-name ir-dispatcher --environment "Variables={DRY_RUN=true,ALLOW_SAMPLE_FINDINGS=true,REQUIRE_SANDBOX_TAG=true,EVIDENCE_BUCKET=$BUCKET,ISOLATION_SG_ID=$SG,SNS_TOPIC_ARN=arn:aws:sns:${REGION}:${ACCOUNT}:ir-alerts,AUTOMATION_ROLE_ARN=arn:aws:iam::${ACCOUNT}:role/ir-forensics-automation-role}"
$DET = aws guardduty list-detectors --query "DetectorIds[0]" --output text
aws guardduty create-sample-findings --detector-id $DET --finding-types "CryptoCurrency:EC2/BitcoinTool.B!DNS"
```

Sample findings point at fake resources, so expect `skipped: resource_not_found` or `out_of_scope` records. That still proves GuardDuty -> EventBridge -> Lambda -> S3 works. Turn `ALLOW_SAMPLE_FINDINGS` off afterwards.

`update-function-configuration --environment` replaces **all** variables, so always pass the full list.

## 3. Going live (scenario week only, agreed with the team)

Set `DRY_RUN=false` with the same command as step f, sandbox account only. Check both DLQs daily:

```powershell
aws sqs get-queue-attributes --queue-url https://sqs.$REGION.amazonaws.com/$ACCOUNT/ir-lambda-dlq --attribute-names ApproximateNumberOfMessages
```

## Not done yet (planned)

| Item | When |
|---|---|
| Team decision: keep automatic key deactivation (rule `ir-auto-contain-keys`) or make it an analyst click | 6 Nov |
| Confirm `userName` = role name with a real temporary-credential finding | Scenario week |
| IaC version of these CLI steps | 26 - 30 Nov |
| Live tests against the Week 3 scenario resources | 26 - 30 Nov |

## Reversing a containment

Every record has `previous_state`. To undo by hand:

- EC2: `aws ec2 modify-instance-attribute --instance-id <id> --groups <original sg ids>`
- Access key: `aws iam update-access-key --user-name <user> --access-key-id <key> --status Active`
- Sessions: `aws iam delete-role-policy` / `delete-user-policy` with policy name `IrRevokeOlderSessions`
- S3: `aws s3api put-public-access-block` with the saved `public_access_block` values
