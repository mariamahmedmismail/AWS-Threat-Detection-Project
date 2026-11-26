"""Outputs: action record (I6), Security Hub update (I7), SNS message (I8). API doc section 6."""
import json
import re

from aws import client
from config import Settings
from normalize import Finding
from playbooks import next_analyst_actions

RECORD_VERSION = "1.0"


def safe_id(finding_id: str) -> str:
    """Security Hub finding IDs are ARNs; make them safe for S3 key prefixes."""
    return re.sub(r"[^A-Za-z0-9._-]", "_", finding_id)[:200]


def build_record(f: Finding, s: Settings, steps, previous_state, result, started, finished, request_id, reason=None):
    return {
        "record_version": RECORD_VERSION,
        "finding_id": f.finding_id,
        "finding_type": f.finding_type,
        "severity": f.severity,
        "source": f.source,
        "triggered_by": f.triggered_by,
        "requested_action": f.requested_action,
        "resource": {"type": f.resource_type or f.raw_resource_type, "id": f.resource_id,
                     "user_name": f.user_name, "account_id": f.account_id, "region": f.region},
        "dry_run": s.dry_run,
        "finding_created_at": f.created_at,     # with finished_at: time from detection to containment
        "started_at": started,
        "evidence": [],                         # [{uri, sha256, collected_at}] for chain of custody
        "finished_at": finished,
        "steps": steps,
        "previous_state": previous_state,
        "result": result,
        "reason": reason,
        "lambda_request_id": request_id,
    }


def write_record(s: Settings, record: dict) -> str:
    # Layout: actions/<finding>/<result>/<started_at>-<request id>.json
    # The result is a folder so the idempotency check can list keys without reading files,
    # and the request id keeps two runs in the same second from overwriting each other.
    ts = record["started_at"].replace(":", "-")
    req = re.sub(r"[^A-Za-z0-9-]", "", str(record["lambda_request_id"]))[:36]
    key = f"actions/{safe_id(record['finding_id'])}/{record['result']}/{ts}-{req}.json"
    client("s3").put_object(Bucket=s.evidence_bucket, Key=key,
                            Body=json.dumps(record, default=str, indent=2).encode(),
                            ContentType="application/json")
    return f"s3://{s.evidence_bucket}/{key}"


def previous_results(s: Settings, f: Finding) -> set[str]:
    """Results of earlier runs for this finding, read from the record keys."""
    res = client("s3").list_objects_v2(Bucket=s.evidence_bucket, Prefix=f"actions/{safe_id(f.finding_id)}/")
    # Key: actions/<finding>/<result>/<file>  ->  the result is the second-to-last segment
    return {obj["Key"].split("/")[-2] for obj in res.get("Contents", []) if obj["Key"].count("/") >= 3}


def update_security_hub(f: Finding, s: Settings, record: dict, record_uri: str) -> None:
    if not f.sh_identifier:
        return
    done = [f"{st['action']}:{st['status']}" for st in record["steps"]]
    text = f"ir-dispatcher ({'DRY RUN' if s.dry_run else 'LIVE'}) {record['result']}: {', '.join(done)}. {record_uri}"
    kwargs = {"FindingIdentifiers": [f.sh_identifier],
              "Note": {"Text": text[:512], "UpdatedBy": "ir-dispatcher"}}
    if not s.dry_run:                       # dry run adds a note but does not change the workflow status
        kwargs["Workflow"] = {"Status": "NOTIFIED"}
    client("securityhub", f.region).batch_update_findings(**kwargs)


def severity_label(sev: float) -> str:
    return "CRITICAL" if sev >= 9 else "HIGH" if sev >= 7 else "MEDIUM" if sev >= 4 else "LOW"


def publish(f: Finding, s: Settings, record: dict, record_uri: str) -> None:
    label = {"dry_run": "planned (dry run)", "ok": "contained", "partial": "PARTIALLY contained",
             "skipped": "skipped"}.get(record["result"], record["result"])
    subject = f"[IR][{severity_label(f.severity)}] {f.resource_type or 'Resource'} {f.resource_id} {label}"
    message = {
        "subject": subject,
        "finding_id": f.finding_id,
        "finding_type": f.finding_type,
        "severity": f.severity,
        "resource": f.resource_id,
        "triggered_by": f.triggered_by,
        "result": record["result"],
        "reason": record.get("reason"),
        "steps": [f"{st['action']}: {st['status']}" for st in record["steps"]],
        "next_analyst_actions": next_analyst_actions(f) if f.triggered_by == "auto" else [],
        "record": record_uri,
    }
    client("sns", f.region).publish(
        TopicArn=s.sns_topic_arn,
        Subject=subject[:100],
        Message=json.dumps(message, default=str, indent=2),
        MessageAttributes={"severity": {"DataType": "Number", "StringValue": str(f.severity)},
                           "result": {"DataType": "String", "StringValue": record["result"]}},
    )
