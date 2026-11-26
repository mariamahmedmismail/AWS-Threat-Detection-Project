"""Turn GuardDuty and Security Hub events into one finding shape (API doc section 4.4).

Two routing rules come from the GuardDuty documentation (checked 1 Nov 2026):
- S3 findings whose data source is CloudTrail *management* events (for example
  Policy:S3/BucketAnonymousAccessGranted) have resourceType "AccessKey", not "S3Bucket".
  The bucket is in resource.s3BucketDetails. Those findings are about the bucket, so they
  are routed to the S3 playbook. The access key is only the identity that changed it.
- Access-key findings can concern temporary credentials (userType "AssumedRole", for example
  InstanceCredentialExfiltration). Those cannot be deactivated with UpdateAccessKey; they are
  contained by revoking the role's sessions instead.
"""
from dataclasses import dataclass, field
from typing import Optional


class UnsupportedEvent(Exception):
    """The event is not a GuardDuty finding or a Security Hub custom action."""


SUPPORTED_TYPES = ("Instance", "AccessKey", "S3Bucket")

# ASFF resource types -> our resource_type
ASFF_TYPES = {"AwsEc2Instance": "Instance", "AwsIamAccessKey": "AccessKey", "AwsS3Bucket": "S3Bucket"}

# ASFF severity labels -> GuardDuty-style number (fallback when Severity.Normalized is missing)
LABEL_SEVERITY = {"CRITICAL": 9.0, "HIGH": 7.0, "MEDIUM": 4.0, "LOW": 1.0, "INFORMATIONAL": 0.0}


@dataclass
class Finding:
    finding_id: str
    source: str                      # "guardduty" | "securityhub-custom-action"
    finding_type: str                # always in GuardDuty format, e.g. "Backdoor:EC2/C&CActivity.B"
    severity: float                  # 0 - 10
    resource_type: Optional[str]     # "Instance" | "AccessKey" | "S3Bucket" | None (unsupported)
    resource_id: Optional[str]
    user_name: Optional[str]         # IAM user name, or role name for temporary credentials
    account_id: str
    region: str
    triggered_by: str                # "auto" | "analyst"
    user_type: Optional[str] = None  # "IAMUser" | "AssumedRole" | "Root" | ... (access keys only)
    requested_action: Optional[str] = None
    is_sample: bool = False
    sh_identifier: Optional[dict] = None
    raw_resource_type: Optional[str] = field(default=None, repr=False)

    created_at: Optional[str] = None  # when GuardDuty created the finding (for time-to-contain KPIs)

    @property
    def is_root(self) -> bool:
        return self.resource_type == "AccessKey" and self.user_type == "Root"

    @property
    def is_temporary_credentials(self) -> bool:
        return self.resource_type == "AccessKey" and self.user_type not in (None, "IAMUser", "Root")


def normalize_event(event: dict) -> list[Finding]:
    source = event.get("source")
    detail_type = event.get("detail-type")
    if source == "aws.guardduty" and detail_type == "GuardDuty Finding":
        return [_from_guardduty(event["detail"])]
    if source == "aws.securityhub" and detail_type == "Security Hub Findings - Custom Action":
        detail = event["detail"]
        return [_from_asff(f, detail.get("actionName")) for f in detail.get("findings", [])]
    raise UnsupportedEvent(f"Unsupported event: source={source!r} detail-type={detail_type!r}")


def _is_s3_finding(finding_type: str) -> bool:
    return ":S3/" in finding_type


def _from_guardduty(d: dict) -> Finding:
    res = d.get("resource", {})
    ftype = d.get("type", "")
    rtype = res.get("resourceType")
    buckets = res.get("s3BucketDetails") or []
    rid, user, user_type = None, None, None

    if _is_s3_finding(ftype) and buckets:
        rtype, rid = "S3Bucket", buckets[0].get("name")
    elif rtype == "Instance":
        rid = res.get("instanceDetails", {}).get("instanceId")
    elif rtype == "AccessKey":
        key = res.get("accessKeyDetails", {})
        rid, user, user_type = key.get("accessKeyId"), key.get("userName"), key.get("userType")

    sample = bool(d.get("service", {}).get("additionalInfo", {}).get("sample", False))
    return Finding(
        finding_id=d["id"],
        source="guardduty",
        finding_type=ftype,
        severity=float(d.get("severity", 0)),
        resource_type=rtype if rtype in SUPPORTED_TYPES else None,
        resource_id=rid,
        user_name=user,
        user_type=user_type,
        account_id=d.get("accountId", ""),
        region=d.get("region", ""),
        triggered_by="auto",
        is_sample=sample,
        raw_resource_type=res.get("resourceType"),
        created_at=d.get("createdAt"),
    )


def asff_type_to_guardduty(asff_type: str) -> str:
    """'TTPs/Command and Control/Backdoor:EC2-C&CActivity.B' -> 'Backdoor:EC2/C&CActivity.B'.

    Security Hub replaces the '/' in GuardDuty type names with '-' and prefixes a category path.
    GuardDuty resource segments (EC2, IAMUser, S3, ...) contain no '-', so the first '-' after
    the ':' is the original '/'.
    """
    name = asff_type.split("/")[-1]
    if ":" in name:
        purpose, rest = name.split(":", 1)
        name = f"{purpose}:{rest.replace('-', '/', 1)}"
    return name


def _from_asff(f: dict, action_name: Optional[str]) -> Finding:
    finding_type = asff_type_to_guardduty((f.get("Types") or [""])[0])
    resources = f.get("Resources") or [{}]
    # Prefer the bucket for S3 findings (they also list the access key that changed it).
    res = next((r for r in resources if _is_s3_finding(finding_type) and r.get("Type") == "AwsS3Bucket"),
               next((r for r in resources if r.get("Type") in ASFF_TYPES), resources[0]))

    rtype = ASFF_TYPES.get(res.get("Type"))
    raw_id = res.get("Id", "")
    user, user_type = None, None
    if rtype == "Instance":
        rid = raw_id.split("/")[-1]                 # arn:aws:ec2:region:acct:instance/i-...
    elif rtype == "S3Bucket":
        rid = raw_id.split(":::")[-1]               # arn:aws:s3:::bucket-name
    elif rtype == "AccessKey":
        details = res.get("Details", {}).get("AwsIamAccessKey", {})
        rid = details.get("AccessKeyId") or raw_id.replace("/", ":").split(":")[-1]
        user = details.get("PrincipalName") or details.get("UserName")
        user_type = details.get("PrincipalType")
    else:
        rid = raw_id or None

    sev = f.get("Severity", {})
    severity = float(sev["Normalized"]) / 10 if "Normalized" in sev else LABEL_SEVERITY.get(sev.get("Label"), 0.0)

    return Finding(
        finding_id=f["Id"],
        source="securityhub-custom-action",
        finding_type=finding_type,
        severity=severity,
        resource_type=rtype,
        resource_id=rid,
        user_name=user,
        user_type=user_type,
        account_id=f.get("AwsAccountId", ""),
        region=f.get("Region", ""),
        triggered_by="analyst",
        requested_action=action_name,
        sh_identifier={"Id": f["Id"], "ProductArn": f.get("ProductArn", "")},
        raw_resource_type=res.get("Type"),
        created_at=f.get("CreatedAt"),
    )
