# Technology Stack

**Project:** DEPI Project 4 - AWS Threat Detection, Monitoring, Incident Response and Forensics
**Document owner:** Ganna | **Version:** 1.0 | **Date:** 2026-10-31

## 1. Overview

The whole lab runs inside one AWS account in the Europe (Stockholm) region, `eu-north-1`. The stack is grouped by layer: logging, storage and analysis, detection, response, notification, and supporting tools. Status shows what is already built and what other members will add.

## 2. Stack by layer

| Layer | Technology | Purpose | Owner | Status |
|---|---|---|---|---|
| Cloud platform | AWS, single account, project "For Each and Every", Free Plan | Hosts the whole lab | Ganna | Built |
| Audit logging | AWS CloudTrail: trail `main-trail`, multi-region, management events (read and write), log file validation | Records every API call in the account | Ganna | Built |
| Configuration tracking | AWS Config: recorder on, all resource types, continuous recording, IAM resources included | Records how resources change over time | Ganna | Built |
| Network logging | VPC Flow Logs on the lab VPC `main-vpc`, all traffic, 10-minute interval | Records network traffic metadata | Ganna | Built |
| Log storage | Amazon S3: separate buckets for CloudTrail, Config and Flow Logs; default encryption (SSE-S3); versioning and a 90-day lifecycle rule on the trail bucket | Central, protected log store | Ganna | Built |
| Log analysis | Amazon Athena | SQL queries that rebuild incident timelines from CloudTrail | Ganna with Menna | Planned |
| Threat detection | Amazon GuardDuty, AWS Security Hub, AWS Config rules, Amazon Inspector, Amazon Macie | Generate and aggregate security findings | Mariam | Planned |
| Automated response | Amazon EventBridge, AWS Lambda, AWS Systems Manager Automation | Quarantine and containment when a finding appears | Muhammad | Planned |
| Notification | Amazon SNS, Security Hub custom actions | Alerts and manual response actions for analysts | Abdullah | Planned |
| Cost control | AWS Budgets: monthly budget of $25 with three alerts | Prevents surprise bills | Ganna | Built |
| Identity and access | AWS Builder ID with MFA, team members invited per project | Individual logins for every member, so actions can be attributed | Ganna | Built |
| Source control and CI/CD | GitHub, GitHub Actions | Code, documents and pipelines | Ganna | Planned |
| Diagrams and documents | Markdown with Mermaid diagrams (rendered by GitHub) | Design documentation | All | In use |

## 3. Why these choices

- **CloudTrail, Config and Flow Logs together:** they answer three different questions: who did what (API calls), what changed (configuration), and what traffic moved (network). An investigation needs all three.
- **S3 as the single log store:** cheap, durable, and every analysis service can read from it. Versioning and lifecycle rules protect the logs as evidence and control cost.
- **Athena:** queries logs in place with SQL, so there is no database to run or pay for between labs.
- **Native AWS detection services:** GuardDuty, Security Hub and Config rules need no servers, work from the same logs, and map findings to known techniques.
- **EventBridge, Lambda and Systems Manager:** serverless automation, so response runs only when a finding appears and costs almost nothing when idle.

## 4. Constraints and decisions

- **Free Plan account:** the account has limited credits and the plan ends on 27 Apr 2027. It must be upgraded to a paid plan before then.
- **No AWS Organization:** joining an Organization would upgrade the plan and expire the free credits, so the trail is a single-account multi-region trail instead of an organization trail.
- **No customer-managed encryption key:** logs use S3 default encryption (SSE-S3). SSE-KMS with a customer-managed key is the production choice and was left out for cost.
- **Management events only:** S3 data events and CloudTrail Insights are off for cost. S3 data events can be enabled for the public-bucket scenario if needed.
