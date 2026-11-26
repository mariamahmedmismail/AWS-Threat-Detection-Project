"""Settings read from environment variables (API doc section 4.2)."""
import os
from dataclasses import dataclass


class ConfigError(Exception):
    """A required environment variable is missing."""


def _flag(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes")


@dataclass(frozen=True)
class Settings:
    dry_run: bool
    evidence_bucket: str
    isolation_sg_id: str
    sns_topic_arn: str
    forensics_document: str
    automation_role_arn: str
    allow_sample_findings: bool
    require_sandbox_tag: bool


def load() -> Settings:
    # Fail safe: anything other than an explicit "false" keeps dry-run ON.
    dry_run = os.environ.get("DRY_RUN", "true").strip().lower() != "false"

    missing = [v for v in ("EVIDENCE_BUCKET", "ISOLATION_SG_ID", "SNS_TOPIC_ARN", "AUTOMATION_ROLE_ARN")
               if not os.environ.get(v)]
    if missing:
        raise ConfigError(f"Missing environment variables: {', '.join(missing)}")

    return Settings(
        dry_run=dry_run,
        evidence_bucket=os.environ["EVIDENCE_BUCKET"],
        isolation_sg_id=os.environ["ISOLATION_SG_ID"],
        sns_topic_arn=os.environ["SNS_TOPIC_ARN"],
        forensics_document=os.environ.get("FORENSICS_DOCUMENT", "IR-CollectEC2Forensics"),
        automation_role_arn=os.environ["AUTOMATION_ROLE_ARN"],
        allow_sample_findings=_flag("ALLOW_SAMPLE_FINDINGS", False),
        require_sandbox_tag=_flag("REQUIRE_SANDBOX_TAG", True),
    )
