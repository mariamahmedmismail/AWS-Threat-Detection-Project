"""Which steps run for which finding (API doc sections 4.5 and 4.6).

Order rules:
- Evidence steps come first. If an evidence step fails, later containment steps are skipped.
- tag_resource comes LAST, so the "ir:status=contained" tag (used by the duplicate check)
  is only written after the containment steps have run. If any of them failed, the tag says
  "containment-incomplete" instead, and a later event will try again.
"""
from dataclasses import dataclass

from normalize import Finding


@dataclass(frozen=True)
class StepSpec:
    action: str
    evidence: bool = False      # True = must succeed before containment steps run


TAG = StepSpec("tag_resource")

EC2_AUTO = [
    StepSpec("capture_instance_metadata", evidence=True),
    StepSpec("snapshot_volumes", evidence=True),
    StepSpec("swap_security_group"),
]
IAM_USER_AUTO = [StepSpec("deactivate_access_key")]
S3_AUTO = [
    StepSpec("capture_bucket_config", evidence=True),
    StepSpec("block_public_access"),
]


def plan(f: Finding) -> list[StepSpec]:
    analyst = f.triggered_by == "analyst"
    if f.requested_action == "CollectForensics" and f.resource_type != "Instance":
        return []        # defence in depth: the handler already skips this case

    if f.resource_type == "Instance":
        if analyst and f.requested_action == "CollectForensics":
            return [StepSpec("capture_instance_metadata", evidence=True), StepSpec("start_forensics")]
        return EC2_AUTO + ([StepSpec("revoke_role_sessions")] if analyst else []) + [TAG]

    if f.resource_type == "AccessKey":
        if f.is_temporary_credentials:
            # Temporary (role) credentials cannot be deactivated; revoking the role's sessions
            # is the containment. That is an analyst-approved step in our design.
            return [StepSpec("revoke_principal_role_sessions"), TAG] if analyst else []
        return IAM_USER_AUTO + ([StepSpec("revoke_user_sessions")] if analyst else []) + [TAG]

    if f.resource_type == "S3Bucket":
        return S3_AUTO + [TAG]

    return []


# Analyst-only steps suggested in notifications after an automatic run
def next_analyst_actions(f: Finding) -> list[str]:
    if f.resource_type == "Instance":
        return ["revoke_role_sessions", "start_forensics", "network_acl_deny (cuts tracked connections)"]
    if f.resource_type == "AccessKey":
        return ["revoke_principal_role_sessions"] if f.is_temporary_credentials else ["revoke_user_sessions"]
    if f.resource_type == "S3Bucket":
        return ["review_bucket_policy_and_acl"]
    return []
