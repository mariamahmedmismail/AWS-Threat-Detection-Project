"""Containment and evidence actions (API doc section 4.6).

Each action takes (finding, settings, ctx) and returns a short detail string.
`ctx` is a dict shared across the steps of one run; actions put "previous_state" in it
so every change can be reversed later. Actions raise on failure; the handler records the error.

Nothing here ever deletes a resource.
"""
import hashlib
import json
from datetime import datetime, timezone

from botocore.exceptions import ClientError

from aws import client
from config import Settings
from normalize import Finding

TAG_STATUS = "ir:status"
TAG_FINDING = "ir:finding-id"


def _safe_id(finding_id: str) -> str:
    import re
    return re.sub(r"[^A-Za-z0-9._-]", "_", finding_id)[:200]


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _deny_older_sessions_policy() -> str:
    """Deny everything for credentials issued before now (revokes existing sessions)."""
    return json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "IrRevokeOlderSessions",
            "Effect": "Deny",
            "Action": "*",
            "Resource": "*",
            "Condition": {"DateLessThan": {"aws:TokenIssueTime": _now()}},
        }],
    })


def _save_evidence(s: Settings, f: Finding, name: str, data, ctx: dict) -> str:
    key = f"evidence/{_safe_id(f.finding_id)}/{name}.json"
    body = json.dumps(data, default=str, indent=2).encode()
    digest = hashlib.sha256(body).hexdigest()
    client("s3").put_object(Bucket=s.evidence_bucket, Key=key, Body=body, ContentType="application/json",
                            Metadata={"sha256": digest})
    uri = f"s3://{s.evidence_bucket}/{key}"
    # Chain of custody: every evidence file is listed in the action record with its SHA-256.
    ctx.setdefault("evidence", []).append({"uri": uri, "sha256": digest, "collected_at": _now()})
    return f"{uri} sha256={digest}"


# ---------------- read helpers (also used for scope and idempotency checks) ----------------

def describe_instance(f: Finding) -> dict:
    res = client("ec2", f.region).describe_instances(InstanceIds=[f.resource_id])
    return res["Reservations"][0]["Instances"][0]


def resource_tags(f: Finding) -> dict:
    """Current tags of the resource as {key: value}."""
    if f.resource_type == "Instance":
        return {t["Key"]: t["Value"] for t in describe_instance(f).get("Tags", [])}
    if f.resource_type == "AccessKey":
        if f.is_temporary_credentials:
            tags = client("iam").list_role_tags(RoleName=f.user_name)["Tags"]
        else:
            tags = client("iam").list_user_tags(UserName=f.user_name)["Tags"]
        return {t["Key"]: t["Value"] for t in tags}
    if f.resource_type == "S3Bucket":
        try:
            tags = client("s3").get_bucket_tagging(Bucket=f.resource_id)["TagSet"]
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchTagSet":
                return {}
            raise
        return {t["Key"]: t["Value"] for t in tags}
    return {}


# ---------------- EC2 ----------------

def capture_instance_metadata(f, s, ctx):
    inst = describe_instance(f)
    ctx["instance"] = inst
    ctx.setdefault("previous_state", {})["security_groups"] = [g["GroupId"] for g in inst.get("SecurityGroups", [])]
    return _save_evidence(s, f, "instance-metadata", inst, ctx)


def snapshot_volumes(f, s, ctx):
    res = client("ec2", f.region).create_snapshots(
        InstanceSpecification={"InstanceId": f.resource_id, "ExcludeBootVolume": False},
        Description=f"IR evidence for finding {f.finding_id}",
        TagSpecifications=[{"ResourceType": "snapshot",
                            "Tags": [{"Key": TAG_FINDING, "Value": f.finding_id}]}],
        CopyTagsFromSource="volume",
    )
    ids = [snap["SnapshotId"] for snap in res.get("Snapshots", [])]
    return ",".join(ids) or "no volumes"


def swap_security_group(f, s, ctx):
    """Replace the security groups with the isolation group.

    AWS docs: ModifyInstanceAttribute "can result in an error if the instance has more than one ENI",
    so instances with several network interfaces are isolated interface by interface.
    Security groups are stateful: tracked connections that are already open continue until
    they time out. Cutting them needs a network ACL (analyst step).
    """
    inst = ctx.get("instance") or describe_instance(f)
    enis = inst.get("NetworkInterfaces", [])
    ctx.setdefault("previous_state", {})["eni_security_groups"] = {
        e["NetworkInterfaceId"]: [g["GroupId"] for g in e.get("Groups", [])] for e in enis}
    ec2 = client("ec2", f.region)
    if len(enis) <= 1:
        ec2.modify_instance_attribute(InstanceId=f.resource_id, Groups=[s.isolation_sg_id])
        return s.isolation_sg_id
    for e in enis:
        ec2.modify_network_interface_attribute(NetworkInterfaceId=e["NetworkInterfaceId"], Groups=[s.isolation_sg_id])
    return f"{s.isolation_sg_id} on {len(enis)} interfaces"


def revoke_role_sessions(f, s, ctx):
    inst = ctx.get("instance") or describe_instance(f)
    profile_arn = inst.get("IamInstanceProfile", {}).get("Arn")
    if not profile_arn:
        return "instance has no role"
    profile_name = profile_arn.split("/")[-1]
    roles = client("iam").get_instance_profile(InstanceProfileName=profile_name)["InstanceProfile"]["Roles"]
    for role in roles:
        client("iam").put_role_policy(RoleName=role["RoleName"], PolicyName="IrRevokeOlderSessions",
                                      PolicyDocument=_deny_older_sessions_policy())
    return ",".join(r["RoleName"] for r in roles)


def start_forensics(f, s, ctx):
    res = client("ssm", f.region).start_automation_execution(
        DocumentName=s.forensics_document,
        Parameters={"InstanceId": [f.resource_id], "EvidenceBucket": [s.evidence_bucket],
                    "FindingId": [_safe_id(f.finding_id)], "AutomationAssumeRole": [s.automation_role_arn]},
    )
    return res["AutomationExecutionId"]


def revoke_principal_role_sessions(f, s, ctx):
    """Temporary credentials (AssumedRole): deny everything issued before now on that role."""
    client("iam").put_role_policy(RoleName=f.user_name, PolicyName="IrRevokeOlderSessions",
                                  PolicyDocument=_deny_older_sessions_policy())
    return f.user_name


# ---------------- IAM access key ----------------

def deactivate_access_key(f, s, ctx):
    client("iam").update_access_key(UserName=f.user_name, AccessKeyId=f.resource_id, Status="Inactive")
    ctx.setdefault("previous_state", {})["access_key_status"] = "Active"
    return f"{f.resource_id} -> Inactive"


def revoke_user_sessions(f, s, ctx):
    client("iam").put_user_policy(UserName=f.user_name, PolicyName="IrRevokeOlderSessions",
                                  PolicyDocument=_deny_older_sessions_policy())
    return f.user_name


# ---------------- S3 ----------------

def capture_bucket_config(f, s, ctx):
    s3 = client("s3")
    data = {}
    for name, call in (("policy", lambda: s3.get_bucket_policy(Bucket=f.resource_id)["Policy"]),
                       ("acl", lambda: s3.get_bucket_acl(Bucket=f.resource_id)["Grants"]),
                       ("public_access_block",
                        lambda: s3.get_public_access_block(Bucket=f.resource_id)["PublicAccessBlockConfiguration"])):
        try:
            data[name] = call()
        except ClientError as e:
            data[name] = f"none ({e.response['Error']['Code']})"   # e.g. no policy set: still valid evidence
    ctx.setdefault("previous_state", {})["public_access_block"] = data["public_access_block"]
    return _save_evidence(s, f, "bucket-config", data, ctx)


def block_public_access(f, s, ctx):
    client("s3").put_public_access_block(
        Bucket=f.resource_id,
        PublicAccessBlockConfiguration={"BlockPublicAcls": True, "IgnorePublicAcls": True,
                                        "BlockPublicPolicy": True, "RestrictPublicBuckets": True},
    )
    return "all four settings enabled"


# ---------------- shared ----------------

def tag_resource(f, s, ctx):
    # Runs last. Only "contained" stops later automatic runs; an incomplete run can be retried.
    status = "containment-incomplete" if ctx.get("failures") else "contained"
    tags = {TAG_STATUS: status, TAG_FINDING: f.finding_id[:256]}
    if f.resource_type == "Instance":
        client("ec2", f.region).create_tags(Resources=[f.resource_id],
                                            Tags=[{"Key": k, "Value": v} for k, v in tags.items()])
    elif f.resource_type == "AccessKey" and f.is_temporary_credentials:
        client("iam").tag_role(RoleName=f.user_name, Tags=[{"Key": k, "Value": v} for k, v in tags.items()])
    elif f.resource_type == "AccessKey":
        client("iam").tag_user(UserName=f.user_name, Tags=[{"Key": k, "Value": v} for k, v in tags.items()])
    elif f.resource_type == "S3Bucket":
        # PutBucketTagging replaces all tags, so merge with the existing ones.
        current = resource_tags(f)
        current.update(tags)
        client("s3").put_bucket_tagging(Bucket=f.resource_id,
                                        Tagging={"TagSet": [{"Key": k, "Value": v} for k, v in current.items()]})
    return ", ".join(f"{k}={v}" for k, v in tags.items())


REGISTRY = {fn.__name__: fn for fn in (
    capture_instance_metadata, snapshot_volumes, swap_security_group, revoke_role_sessions, start_forensics,
    revoke_principal_role_sessions,
    deactivate_access_key, revoke_user_sessions, capture_bucket_config, block_public_access, tag_resource,
)}


def error_code(exc: Exception) -> str:
    """Map AWS errors to the step error codes in API doc section 4.7."""
    if isinstance(exc, ClientError):
        code = exc.response["Error"]["Code"]
        if code in ("AccessDenied", "AccessDeniedException", "UnauthorizedOperation"):
            return "ACCESS_DENIED"
        if "NotFound" in code or "Malformed" in code or code in ("NoSuchEntity", "NoSuchBucket"):
            return "RESOURCE_NOT_FOUND"
        if code in ("Throttling", "ThrottlingException", "RequestLimitExceeded", "SlowDown"):
            return "THROTTLED"
    return "UNKNOWN"
