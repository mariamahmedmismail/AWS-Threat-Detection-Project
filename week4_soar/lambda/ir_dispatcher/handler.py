"""ir-dispatcher: automated incident response for GuardDuty / Security Hub findings.

Entry point: handler.lambda_handler. Behaviour follows docs/api-interface-documentation.md, section 4.
DRY_RUN is ON unless the environment variable DRY_RUN is exactly "false".
"""
import json
import logging
import os
from datetime import datetime, timezone

from botocore.exceptions import ClientError

import actions
import config
import records
from normalize import Finding, UnsupportedEvent, normalize_event
from playbooks import plan

log = logging.getLogger()
log.setLevel(os.environ.get("LOG_LEVEL", "INFO"))


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _log(event: str, **fields) -> None:
    log.info(json.dumps({"event": event, **fields}, default=str))


def lambda_handler(event, context):
    settings = config.load()
    request_id = getattr(context, "aws_request_id", "local")
    try:
        findings = normalize_event(event)
    except UnsupportedEvent as e:
        # Not retryable: retrying the same unsupported event would fail again.
        _log("unsupported_event", error=str(e))
        return {"results": [], "status": "skipped", "reason": "unsupported_event"}

    results = [process(f, settings, request_id) for f in findings]
    return {"results": results}


def process(f: Finding, s: config.Settings, request_id: str) -> dict:
    started = _now()
    _log("finding_received", finding_id=f.finding_id, type=f.finding_type, resource=f.resource_id,
         triggered_by=f.triggered_by, dry_run=s.dry_run)

    # 1-4: decide whether to act at all
    reason = _skip_reason(f, s)
    if reason == "already_contained":
        # GuardDuty re-sends updated findings; logging is enough, no new record or alert.
        _log("skipped", finding_id=f.finding_id, reason=reason)
        return {"status": "skipped", "finding_id": f.finding_id, "reason": reason}
    if reason:
        record = records.build_record(f, s, [], {}, "skipped", started, _now(), request_id, reason)
        uri = records.write_record(s, record)
        if reason in ALERT_REASONS or (reason == "out_of_scope" and f.severity >= 7):
            _safe(records.publish, f, s, record, uri)
        _log("skipped", finding_id=f.finding_id, reason=reason, record=uri)
        return {"status": "skipped", "finding_id": f.finding_id, "reason": reason, "record_key": uri}

    # 5-6: plan and execute
    steps, ctx, evidence_failed = [], {}, False
    for spec in plan(f):
        step = {"action": spec.action, "target": f.resource_id, "status": "planned", "detail": None, "error": None}
        if s.dry_run:
            pass
        elif evidence_failed and not spec.evidence and spec.action != "tag_resource":
            step.update(status="skipped", error="PRECONDITION_FAILED", detail="an evidence step failed")
            ctx["failures"] = ctx.get("failures", 0) + 1
        else:
            try:
                step.update(status="done", detail=actions.REGISTRY[spec.action](f, s, ctx))
            except Exception as e:   # record every failure; never hide later steps
                step.update(status="failed", error=actions.error_code(e), detail=str(e)[:300])
                evidence_failed = evidence_failed or spec.evidence
                ctx["failures"] = ctx.get("failures", 0) + 1
        steps.append(step)
        _log("step", finding_id=f.finding_id, **step)

    if s.dry_run:
        result = "dry_run"
    elif any(st["status"] in ("failed", "skipped") for st in steps):
        result = "partial"
    else:
        result = "ok"

    # 7: record (must succeed, otherwise raise so Lambda retries), then report (best effort)
    record = records.build_record(f, s, steps, ctx.get("previous_state", {}), result, started, _now(), request_id)
    record["evidence"] = ctx.get("evidence", [])
    uri = records.write_record(s, record)
    _safe(records.update_security_hub, f, s, record, uri)
    _safe(records.publish, f, s, record, uri)

    summary = {"status": result, "finding_id": f.finding_id, "record_key": uri,
               "steps_done": sum(st["status"] == "done" for st in steps),
               "steps_failed": sum(st["status"] == "failed" for st in steps)}
    _log("finished", **summary)
    return summary


# Skips that a human must hear about. out_of_scope is added when severity >= 7, because during the
# scenario week one forgotten env=sandbox tag would otherwise make the automation do nothing silently.
ALERT_REASONS = ("unsupported_resource", "resource_not_found", "temporary_credentials_need_analyst",
                 "root_credentials_need_analyst", "action_not_applicable", "resource_already_contained",
                 "scope_check_denied")


def _skip_reason(f: Finding, s: config.Settings) -> str | None:
    if f.resource_type is None or not f.resource_id:
        return "unsupported_resource"
    if f.requested_action == "CollectForensics" and f.resource_type != "Instance":
        return "action_not_applicable"      # forensics exists for EC2 only; never fall back to containment
    if f.is_root:
        return "root_credentials_need_analyst"   # root keys/sessions are handled by a person, never automated
    if f.is_sample and not s.allow_sample_findings:
        return "sample_finding"
    if f.resource_type == "AccessKey" and not f.user_name:
        return "unsupported_resource"      # cannot act on a key without its user name
    if f.is_temporary_credentials and f.triggered_by == "auto":
        return "temporary_credentials_need_analyst"

    try:
        tags = actions.resource_tags(f)
    except ClientError as e:
        code = actions.error_code(e)
        if code == "RESOURCE_NOT_FOUND":
            return "resource_not_found"
        if code == "ACCESS_DENIED":
            # Permanent: retrying cannot help (e.g. an SCP region block). Record and alert instead of crashing.
            return "scope_check_denied"
        raise                                  # transient (throttling etc.): let Lambda retry, then the DLQ

    if s.require_sandbox_tag and tags.get("env") != "sandbox":
        return "out_of_scope"

    # Idempotency: analysts may always re-run on purpose; automatic duplicates are skipped.
    if f.triggered_by == "auto":
        if tags.get(actions.TAG_STATUS) == "contained":
            if tags.get(actions.TAG_FINDING) == f.finding_id[:256]:
                return "already_contained"           # same finding re-sent: log only
            return "resource_already_contained"      # a DIFFERENT finding on a contained resource: record + alert
        done = records.previous_results(s, f)
        if (s.dry_run and "dry_run" in done) or (not s.dry_run and "ok" in done):
            return "already_contained"
    return None


def _safe(fn, *args) -> None:
    """Reporting must not break containment: log the failure and carry on."""
    try:
        fn(*args)
    except Exception as e:
        _log("report_failed", step=fn.__name__, error=str(e)[:300])
