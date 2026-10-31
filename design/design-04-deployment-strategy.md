# Deployment Strategy

**Project:** DEPI Project 4 - AWS Threat Detection, Monitoring, Incident Response and Forensics
**Document owner:** Ganna | **Version:** 1.0 | **Date:** 2026-10-31

## 1. Approach

The platform is deployed in layers, from the evidence up to the response. Each layer depends on the one before it, so the order matters: detection needs logs, and automation needs findings. All resources live in one AWS account in `eu-north-1`.

## 2. Deployment order

| Step | Layer | What is deployed | Owner | Status |
|---|---|---|---|---|
| 1 | Cost control | AWS Budgets: monthly budget of $25 with three alerts, alert email verified | Ganna | Done |
| 2 | Access | MFA on the account login; every member invited with their own AWS Builder ID | Ganna | Done |
| 3 | Audit logging | CloudTrail `main-trail` (multi-region, management events, log file validation) delivering to its own S3 bucket | Ganna | Done |
| 4 | Log protection | S3 versioning and a 90-day lifecycle rule on the trail bucket | Ganna | Done |
| 5 | Configuration tracking | AWS Config recorder, all resource types, IAM included, delivering to its own bucket | Ganna | Done |
| 6 | Network logging | VPC Flow Logs on `main-vpc`, delivering to its own bucket | Ganna | Done |
| 7 | Detection | GuardDuty, Security Hub, Config rules, Inspector, Macie | Mariam | Planned |
| 8 | Analysis | Athena queries over the CloudTrail logs | Ganna with Menna | Planned |
| 9 | Automation | EventBridge rule, Lambda quarantine function, Systems Manager Automation | Muhammad | Planned |
| 10 | Notification | SNS topics and subscriptions, Security Hub custom actions | Abdullah | Planned |
| 11 | Scenarios | Compromised EC2, exposed access keys, public S3 bucket | Menna, Esraa | Planned |

Logging and detection are switched on early so GuardDuty and Config have time to produce findings before the scenarios run.

## 3. How it is deployed

- **Method:** resources were created through the AWS console, following the steps and settings recorded in this team's documentation.
- **Reproducibility:** the settings of every built component are listed in the technology stack and architecture documents. Console actions are to be captured as scripts or infrastructure-as-code and committed to GitHub before the 30 Nov implementation freeze.
- **Source control:** documents, scripts and code are committed to the team GitHub repository, with a branching strategy and CI with GitHub Actions (planned, 20-30 Nov).
- **Change control:** every deliverable is peer-reviewed by the member's pair before submission. Scope is frozen on 28 Nov. After that, only fixes and documentation are allowed.

## 4. Cost control

- Monthly budget of $25 with three alerts, so overspending is noticed early.
- The account runs on the AWS Free Plan with a credit balance. The plan ends on 27 Apr 2027 and must be upgraded before then.
- Test EC2 instances are created only for scenarios and terminated afterwards. All test instances are terminated before the midterms (by 13 Nov).
- Only management events are logged. S3 data events, CloudTrail Insights and CloudWatch Logs are off.
- Lifecycle rule removes old log versions and incomplete uploads automatically.
- Logging, GuardDuty and Config may stay on during the midterms. Anything billable that is not needed is shut down after each lab.

## 5. Rollback and recovery

| Situation | Action |
|---|---|
| A logging service is misconfigured | Edit or recreate it. CloudTrail, Config and Flow Logs can be recreated without affecting the buckets and the logs already stored. |
| A log file is overwritten or deleted | Restore the previous version from the versioned trail bucket. |
| Costs rise unexpectedly | Budget alerts notify the team. Stop the recorder or delete the flow log, and terminate test instances. |
| A scenario damages a test instance | Terminate it and launch a clean one. No production data is involved. |
| An automation function misbehaves | Disable the EventBridge rule. Response then becomes manual from Security Hub. |
| An account member leaves or is compromised | Remove the member from the project team and rotate any shared credentials. |

## 6. Risks

| Risk | Impact | Mitigation |
|---|---|---|
| Free Plan ends on 27 Apr 2027 | Account closes unless upgraded | Upgrade to a paid plan directly, not by joining an Organization, so remaining credits are kept |
| A service asks for a paid plan | Delays detection setup | Ask the team to report it immediately and upgrade directly if needed |
| Detection findings arrive late | Scenarios have nothing to analyse | Services switched on early, with time to accumulate findings |
| Team members with broad access make mistakes | Costs or deleted resources | Individual logins, Budget alerts, versioned log bucket |
| Time lost to the midterms (14-19 Nov) | Tasks slip | Nothing is scheduled during midterms. Services keep running. |

## 7. Checkpoints

| Date | Checkpoint |
|---|---|
| 6 Nov | Design documents uploaded to GitHub |
| 13 Nov | CloudTrail, Config and Flow Logs delivering to S3, Athena returns data, test instances terminated, budget alerts working |
| 25 Nov | Three incident scenarios executed, with evidence and timelines documented |
| 28 Nov | Scope freeze |
| 30 Nov | Implementation complete and on GitHub |
| 4 Dec | Final submission |
