"""Tests for ir-dispatcher. Run: python -m pytest -q"""
import json

import pytest

from conftest import load_event


def sg_of(env, instance_id):
    inst = env["ec2"].describe_instances(InstanceIds=[instance_id])["Reservations"][0]["Instances"][0]
    return [g["GroupId"] for g in inst["SecurityGroups"]]


def records(env):
    res = env["s3"].list_objects_v2(Bucket="ir-evidence-bucket", Prefix="actions/")
    return [json.loads(env["s3"].get_object(Bucket="ir-evidence-bucket", Key=o["Key"])["Body"].read())
            for o in res.get("Contents", [])]


# ---------------- normalization ----------------

def test_normalize_all_sample_events():
    from normalize import normalize_event
    expected = {
        "gd-ec2-high.json": ("Instance", "i-0abc1234567890def", None, "auto"),
        "gd-iam-key-medium.json": ("AccessKey", "FAKEUSERKEY0001", "backup", "auto"),
        "gd-s3-public.json": ("S3Bucket", "ir-sandbox-public-bucket", None, "auto"),
        "gd-instance-cred-exfil.json": ("AccessKey", "FAKEROLESESSION0001", "ec2-app-role", "auto"),
        "sh-custom-s3.json": ("S3Bucket", "ir-sandbox-public-bucket", None, "analyst"),
        "gd-unsupported.json": (None, None, None, "auto"),
        "sh-custom-isolate.json": ("Instance", "i-0abc1234567890def", None, "analyst"),
    }
    for name, (rtype, rid, user, trig) in expected.items():
        f = normalize_event(load_event(name))[0]
        assert (f.resource_type, f.resource_id, f.user_name, f.triggered_by) == (rtype, rid, user, trig), name
    sh = normalize_event(load_event("sh-custom-isolate.json"))[0]
    assert sh.severity == 8.0 and sh.requested_action == "IsolateResource" and sh.sh_identifier["ProductArn"]
    assert normalize_event(load_event("gd-ec2-sample.json"))[0].is_sample


def test_unsupported_event_source_is_skipped_not_retried(aws, invoke):
    assert invoke({"source": "aws.ec2", "detail-type": "Something"})["reason"] == "unsupported_event"


# ---------------- configuration safety ----------------

@pytest.mark.parametrize("value,expected", [("true", True), ("TRUE", True), ("no", True), ("maybe", True),
                                            ("", True), ("false", False), (" False ", False)])
def test_dry_run_is_fail_safe(aws, value, expected):
    import config
    aws["monkeypatch"].setenv("DRY_RUN", value)
    assert config.load().dry_run is expected


def test_missing_config_fails_loudly(aws):
    import config
    aws["monkeypatch"].delenv("EVIDENCE_BUCKET")
    with pytest.raises(config.ConfigError):
        config.load()


# ---------------- dry run (the default) ----------------

def test_dry_run_changes_nothing_but_records_plan(aws, invoke):
    out = invoke(load_event("gd-ec2-high.json", **{"i-0abc1234567890def": aws["instance"]}))["results"][0]
    assert out["status"] == "dry_run" and out["steps_done"] == 0
    assert sg_of(aws, aws["instance"]) == [aws["web_sg"]]          # untouched
    rec = records(aws)[0]
    assert rec["dry_run"] is True
    assert [s["action"] for s in rec["steps"]] == ["capture_instance_metadata", "snapshot_volumes",
                                                    "swap_security_group", "tag_resource"]
    assert all(s["status"] == "planned" for s in rec["steps"])


def test_duplicate_event_is_skipped(aws, invoke):
    ev = load_event("gd-ec2-high.json", **{"i-0abc1234567890def": aws["instance"]})
    invoke(ev)
    second = invoke(ev)["results"][0]
    assert second == {"status": "skipped", "finding_id": ev["detail"]["id"], "reason": "already_contained"}
    assert len(records(aws)) == 1                                   # duplicates add no record


def test_sample_findings_ignored_by_default(aws, invoke):
    assert invoke(load_event("gd-ec2-sample.json"))["results"][0]["reason"] == "sample_finding"


def test_non_sandbox_resources_are_out_of_scope(aws, invoke):
    out = invoke(load_event("gd-ec2-high.json", **{"i-0abc1234567890def": aws["prod_instance"]}))["results"][0]
    assert out["reason"] == "out_of_scope"


def test_unsupported_resource_type_is_recorded(aws, invoke):
    out = invoke(load_event("gd-unsupported.json"))["results"][0]
    assert out["reason"] == "unsupported_resource" and records(aws)[0]["result"] == "skipped"


def test_missing_instance_is_reported_not_crashed(aws, invoke):
    out = invoke(load_event("gd-ec2-high.json", **{"i-0abc1234567890def": "i-00000000000000000"}))["results"][0]
    assert out["reason"] == "resource_not_found"


# ---------------- live mode (sandbox only) ----------------

def go_live(aws):
    aws["monkeypatch"].setenv("DRY_RUN", "false")


def test_live_ec2_isolation(aws, invoke):
    go_live(aws)
    ev = load_event("gd-ec2-high.json", **{"i-0abc1234567890def": aws["instance"]})
    out = invoke(ev)["results"][0]
    assert out["status"] == "ok", records(aws)[0]["steps"]
    assert sg_of(aws, aws["instance"]) == [aws["iso_sg"]]
    rec = records(aws)[0]
    assert rec["previous_state"]["security_groups"] == [aws["web_sg"]]   # reversible
    tags = {t["Key"]: t["Value"] for t in aws["ec2"].describe_tags(
        Filters=[{"Name": "resource-id", "Values": [aws["instance"]]}])["Tags"]}
    assert tags["ir:status"] == "contained"
    assert invoke(ev)["results"][0]["reason"] == "already_contained"


def test_live_access_key_deactivated_not_deleted(aws, invoke):
    go_live(aws)
    out = invoke(load_event("gd-iam-key-medium.json", FAKEUSERKEY0001=aws["key_id"]))["results"][0]
    assert out["status"] == "ok"
    keys = aws["iam"].list_access_keys(UserName="backup")["AccessKeyMetadata"]
    assert [(k["AccessKeyId"], k["Status"]) for k in keys] == [(aws["key_id"], "Inactive")]


def test_live_s3_block_public_access_keeps_existing_tags(aws, invoke):
    go_live(aws)
    assert invoke(load_event("gd-s3-public.json"))["results"][0]["status"] == "ok"
    pab = aws["s3"].get_public_access_block(Bucket="ir-sandbox-public-bucket")["PublicAccessBlockConfiguration"]
    assert all(pab.values())
    tags = {t["Key"]: t["Value"] for t in aws["s3"].get_bucket_tagging(Bucket="ir-sandbox-public-bucket")["TagSet"]}
    assert tags["owner"] == "member5" and tags["ir:status"] == "contained"
    evidence = aws["s3"].list_objects_v2(Bucket="ir-evidence-bucket", Prefix="evidence/")["Contents"]
    assert evidence, "bucket configuration must be saved before the change"


def test_analyst_isolate_also_revokes_role_sessions(aws, invoke):
    go_live(aws)
    out = invoke(load_event("sh-custom-isolate.json", **{"i-0abc1234567890def": aws["instance"]}))["results"][0]
    assert out["status"] == "ok", records(aws)[0]["steps"]
    assert "IrRevokeOlderSessions" in aws["iam"].list_role_policies(RoleName="ec2-app-role")["PolicyNames"]


def test_evidence_failure_blocks_containment(aws, invoke, monkeypatch):
    import actions
    go_live(aws)

    def broken(*a):
        raise RuntimeError("snapshot service unavailable")
    monkeypatch.setitem(actions.REGISTRY, "snapshot_volumes", broken)

    out = invoke(load_event("gd-ec2-high.json", **{"i-0abc1234567890def": aws["instance"]}))["results"][0]
    assert out["status"] == "partial"
    steps = {s["action"]: s for s in records(aws)[0]["steps"]}
    assert steps["snapshot_volumes"]["status"] == "failed"
    assert steps["swap_security_group"] == {**steps["swap_security_group"], "status": "skipped",
                                            "error": "PRECONDITION_FAILED"}
    assert sg_of(aws, aws["instance"]) == [aws["web_sg"]]          # not isolated without evidence


# ---------------- rules match the events they should ----------------

def _matches(pattern, event):
    """Minimal EventBridge matcher for the operators our rules use (exact, prefix, numeric)."""
    for key, cond in pattern.items():
        val = event.get(key)
        if isinstance(cond, dict):
            if not isinstance(val, dict) or not _matches(cond, val):
                return False
            continue
        vals = val if isinstance(val, list) else [val]
        ok = False
        for c in cond:
            for v in vals:
                if isinstance(c, dict) and "prefix" in c:
                    ok |= isinstance(v, str) and v.startswith(c["prefix"])
                elif isinstance(c, dict) and "numeric" in c:
                    ops, n = c["numeric"], True
                    for i in range(0, len(ops), 2):
                        op, bound = ops[i], ops[i + 1]
                        n &= {">=": v >= bound, ">": v > bound, "<": v < bound, "<=": v <= bound, "=": v == bound}[op]
                    ok |= n
                else:
                    ok |= v == c
        if not ok:
            return False
    return True


def test_rules_route_events_correctly():
    import pathlib
    rules = {p.stem: json.loads(p.read_text()) for p in (pathlib.Path(__file__).parents[1] / "rules").glob("*.json")}
    assert _matches(rules["ir-auto-contain-high"], load_event("gd-ec2-high.json"))
    assert _matches(rules["ir-auto-contain-keys"], load_event("gd-iam-key-medium.json"))
    assert not _matches(rules["ir-auto-contain-high"], load_event("gd-iam-key-medium.json"))   # Medium by default
    assert _matches(rules["ir-auto-contain-high"], load_event("gd-s3-public.json"))
    assert not _matches(rules["ir-auto-contain-high"], load_event("gd-unsupported.json"))
    sh = load_event("sh-custom-isolate.json")
    assert _matches(rules["ir-analyst-action"], sh) and not _matches(rules["ir-auto-contain-high"], sh)
    medium = load_event("gd-ec2-high.json")
    medium["detail"]["severity"] = 5
    assert _matches(rules["ir-notify"], medium) and not _matches(rules["ir-auto-contain-high"], medium)


# ---------------- fixes from the 1 Nov review (each one is a bug the first version had) ----------------

def test_asff_types_are_converted_back_to_guardduty_names():
    from normalize import asff_type_to_guardduty as conv
    # Examples from the GuardDuty -> Security Hub mapping table in the AWS docs
    assert conv("TTPs/Initial Access/UnauthorizedAccess:EC2-SSHBruteForce") == "UnauthorizedAccess:EC2/SSHBruteForce"
    assert conv("TTPs/Command and Control/Backdoor:EC2-C&CActivity.B") == "Backdoor:EC2/C&CActivity.B"
    assert conv("Unusual Behaviors/VM/Behavior:EC2-NetworkPortUnusual") == "Behavior:EC2/NetworkPortUnusual"


def test_public_bucket_finding_blocks_bucket_and_leaves_admin_key_alone(aws, invoke):
    """GuardDuty reports Policy:S3 findings with resourceType AccessKey. The old code deactivated
    the key of whoever changed the policy and never closed the bucket."""
    go_live(aws)
    out = invoke(load_event("gd-s3-public.json", FAKEADMINKEY0001=aws["admin_key"]))["results"][0]
    assert out["status"] == "ok"
    pab = aws["s3"].get_public_access_block(Bucket="ir-sandbox-public-bucket")["PublicAccessBlockConfiguration"]
    assert all(pab.values())
    key = aws["iam"].list_access_keys(UserName="admin-user")["AccessKeyMetadata"][0]
    assert key["Status"] == "Active"


def test_analyst_action_on_s3_finding_targets_the_bucket(aws, invoke):
    go_live(aws)
    out = invoke(load_event("sh-custom-s3.json"))["results"][0]
    assert out["status"] == "ok"
    assert all(aws["s3"].get_public_access_block(Bucket="ir-sandbox-public-bucket")["PublicAccessBlockConfiguration"].values())


def test_temporary_credentials_are_not_deactivated_automatically(aws, invoke):
    go_live(aws)
    out = invoke(load_event("gd-instance-cred-exfil.json"))["results"][0]
    assert out["reason"] == "temporary_credentials_need_analyst"
    assert aws["iam"].list_role_policies(RoleName="ec2-app-role")["PolicyNames"] == []


def test_analyst_revokes_sessions_for_temporary_credentials(aws, invoke):
    go_live(aws)
    ev = load_event("sh-custom-isolate.json")
    f = ev["detail"]["findings"][0]
    f["Types"] = ["TTPs/Exfiltration/UnauthorizedAccess:IAMUser-InstanceCredentialExfiltration.OutsideAWS"]
    f["Resources"] = [{"Type": "AwsIamAccessKey", "Id": "AWS::IAM::AccessKey:FAKEROLESESSION0001",
                       "Details": {"AwsIamAccessKey": {"AccessKeyId": "FAKEROLESESSION0001",
                                                       "PrincipalName": "ec2-app-role", "PrincipalType": "AssumedRole"}}}]
    out = invoke(ev)["results"][0]
    assert out["status"] == "ok", records(aws)[0]["steps"]
    assert "IrRevokeOlderSessions" in aws["iam"].list_role_policies(RoleName="ec2-app-role")["PolicyNames"]


def test_instance_with_two_network_interfaces_is_fully_isolated(aws, invoke):
    go_live(aws)
    ec2 = aws["ec2"]
    subnet = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [aws["vpc"]]}])["Subnets"][0]["SubnetId"]
    inst = ec2.run_instances(ImageId=aws["ami"], MinCount=1, MaxCount=1, SubnetId=subnet,
                             SecurityGroupIds=[aws["web_sg"]],
                             TagSpecifications=[{"ResourceType": "instance", "Tags": [{"Key": "env", "Value": "sandbox"}]}]
                             )["Instances"][0]["InstanceId"]
    eni = ec2.create_network_interface(SubnetId=subnet, Groups=[aws["web_sg"]])["NetworkInterface"]["NetworkInterfaceId"]
    ec2.attach_network_interface(NetworkInterfaceId=eni, InstanceId=inst, DeviceIndex=1)

    out = invoke(load_event("gd-ec2-high.json", **{"i-0abc1234567890def": inst}))["results"][0]
    assert out["status"] == "ok", records(aws)[0]["steps"]
    enis = ec2.describe_network_interfaces(Filters=[{"Name": "attachment.instance-id", "Values": [inst]}])
    groups = {n["NetworkInterfaceId"]: [g["GroupId"] for g in n["Groups"]] for n in enis["NetworkInterfaces"]}
    # Real AWS REPLACES the interface's groups with the ones given. moto (the mock) appends instead,
    # so here we can only check that every interface received the isolation group.
    assert len(groups) == 2 and all(aws["iso_sg"] in g for g in groups.values()), groups


def test_failed_containment_is_not_marked_contained_and_is_retried(aws, invoke, monkeypatch):
    """The old order tagged 'contained' BEFORE isolating, so a failed isolation was never retried."""
    import actions
    go_live(aws)
    real_swap = actions.REGISTRY["swap_security_group"]

    def broken(*a):
        raise RuntimeError("isolation failed")
    monkeypatch.setitem(actions.REGISTRY, "swap_security_group", broken)
    ev = load_event("gd-ec2-high.json", **{"i-0abc1234567890def": aws["instance"]})
    assert invoke(ev)["results"][0]["status"] == "partial"
    tags = {t["Key"]: t["Value"] for t in aws["ec2"].describe_tags(
        Filters=[{"Name": "resource-id", "Values": [aws["instance"]]}])["Tags"]}
    assert tags["ir:status"] == "containment-incomplete"

    monkeypatch.setitem(actions.REGISTRY, "swap_security_group", real_swap)
    assert invoke(ev)["results"][0]["status"] == "ok"            # GuardDuty re-sends it: retried, now isolated
    assert sg_of(aws, aws["instance"]) == [aws["iso_sg"]]


def test_evidence_keys_are_s3_safe_for_security_hub_ids(aws, invoke):
    go_live(aws)
    invoke(load_event("sh-custom-isolate.json", **{"i-0abc1234567890def": aws["instance"]}))
    keys = [o["Key"] for o in aws["s3"].list_objects_v2(Bucket="ir-evidence-bucket", Prefix="evidence/")["Contents"]]
    assert keys and all(k.count("/") == 2 and ":" not in k for k in keys), keys


# ---------------- fixes from the 2 Nov peer review ----------------

def _rules():
    import pathlib
    return {p.stem: json.loads(p.read_text()) for p in (pathlib.Path(__file__).parents[1] / "rules").glob("*.json")}


# Default severities from the GuardDuty finding-type pages (EC2, IAM, S3), checked 2 Nov 2026.
HIGH_TYPES = [
    "Backdoor:EC2/C&CActivity.B", "Backdoor:EC2/C&CActivity.B!DNS", "Backdoor:EC2/DenialOfService.Dns",
    "Backdoor:EC2/DenialOfService.Tcp", "Backdoor:EC2/DenialOfService.Udp", "Backdoor:EC2/DenialOfService.UdpOnTcpPorts",
    "Backdoor:EC2/DenialOfService.UnusualProtocol", "CryptoCurrency:EC2/BitcoinTool.B", "CryptoCurrency:EC2/BitcoinTool.B!DNS",
    "Impact:EC2/BitcoinDomainRequest.Reputation", "Impact:EC2/MaliciousDomainRequest.Reputation", "Impact:EC2/PortSweep",
    "Trojan:EC2/DGADomainRequest.B", "Trojan:EC2/DGADomainRequest.C!DNS", "Trojan:EC2/DNSDataExfiltration",
    "Trojan:EC2/DriveBySourceTraffic!DNS", "Trojan:EC2/PhishingDomainRequest!DNS",
    "UnauthorizedAccess:EC2/MetadataDNSRebind", "UnauthorizedAccess:EC2/TorClient", "UnauthorizedAccess:EC2/TorRelay",
    "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS",
    "Policy:S3/BucketAnonymousAccessGranted", "Policy:S3/BucketPublicAccessGranted",
]
NOTIFY_ONLY_HIGH = [   # High, but containment would be wrong or is not automated: must still alert
    "Recon:EC2/PortProbeEMRUnprotectedPort",        # the instance is the victim of a probe
    "CredentialAccess:IAMUser/CompromisedCredentials", "Exfiltration:IAMUser/AnomalousBehavior",
    "Impact:IAMUser/AnomalousBehavior",
]


def _gd(ftype, sev):
    ev = load_event("gd-ec2-high.json")
    ev["detail"]["type"], ev["detail"]["severity"] = ftype, sev
    return ev


def test_every_high_ec2_iam_s3_type_is_contained_or_alerted():
    r = _rules()
    for t in HIGH_TYPES:
        assert _matches(r["ir-auto-contain-high"], _gd(t, 8)), f"{t} would not be auto-contained"
    for t in HIGH_TYPES + NOTIFY_ONLY_HIGH:
        assert _matches(r["ir-notify"], _gd(t, 8)), f"{t} would produce no alert"
    assert not _matches(r["ir-auto-contain-high"], _gd("Recon:EC2/PortProbeEMRUnprotectedPort", 8))


def test_nothing_of_severity_4_or_more_is_silent():
    r = _rules()
    for sev in (4, 4.0, 5.5, 6.9, 7, 8.9, 9, 10):
        assert _matches(r["ir-notify"], _gd("Anything:Unknown/NewType", sev))
    assert not _matches(r["ir-notify"], _gd("Anything:Unknown/NewType", 3.9))


def test_medium_exposed_key_is_deactivated(aws, invoke):
    go_live(aws)
    out = invoke(load_event("gd-iam-key-medium.json", FAKEUSERKEY0001=aws["key_id"]))["results"][0]
    assert out["status"] == "ok"
    assert aws["iam"].list_access_keys(UserName="backup")["AccessKeyMetadata"][0]["Status"] == "Inactive"


def test_collect_forensics_never_contains_other_resource_types(aws, invoke):
    go_live(aws)
    ev = load_event("sh-custom-s3.json")
    ev["detail"]["actionName"] = "CollectForensics"
    out = invoke(ev)["results"][0]
    assert out["reason"] == "action_not_applicable"
    with pytest.raises(Exception):    # no Block Public Access configuration was written
        aws["s3"].get_public_access_block(Bucket="ir-sandbox-public-bucket")

    from normalize import normalize_event
    from playbooks import plan
    f = normalize_event(load_event("gd-iam-key-medium.json"))[0]
    f.triggered_by, f.requested_action = "analyst", "CollectForensics"
    assert plan(f) == []


def test_new_finding_on_contained_resource_is_recorded_and_alerted(aws, invoke, monkeypatch):
    import records as rec_mod
    sent = []
    monkeypatch.setattr(rec_mod, "publish", lambda f, s, r, u: sent.append(r["reason"]))
    go_live(aws)
    first = load_event("gd-ec2-high.json", **{"i-0abc1234567890def": aws["instance"]})
    assert invoke(first)["results"][0]["status"] == "ok"
    second = load_event("gd-ec2-high.json", **{"i-0abc1234567890def": aws["instance"]})
    second["detail"]["id"] = "99999999999999999999999999999999"
    second["detail"]["type"] = "Trojan:EC2/DNSDataExfiltration"
    out = invoke(second)["results"][0]
    assert out["reason"] == "resource_already_contained" and "record_key" in out
    assert "resource_already_contained" in sent
    assert invoke(first)["results"][0]["reason"] == "already_contained"      # same finding again: silent


def test_high_severity_out_of_scope_sends_an_alert(aws, invoke, monkeypatch):
    import records as rec_mod
    sent = []
    monkeypatch.setattr(rec_mod, "publish", lambda f, s, r, u: sent.append(r["reason"]))
    out = invoke(load_event("gd-ec2-high.json", **{"i-0abc1234567890def": aws["prod_instance"]}))["results"][0]
    assert out["reason"] == "out_of_scope" and sent == ["out_of_scope"]
    low = load_event("gd-ec2-high.json", **{"i-0abc1234567890def": aws["prod_instance"]})
    low["detail"]["severity"], low["detail"]["id"] = 5, "88888888888888888888888888888888"
    invoke(low)
    assert sent == ["out_of_scope"]                                          # medium + out of scope: record only


def test_root_credentials_are_never_automated(aws, invoke):
    go_live(aws)
    ev = load_event("gd-iam-key-medium.json")
    ev["detail"]["resource"]["accessKeyDetails"].update(userType="Root", userName="Root")
    assert invoke(ev)["results"][0]["reason"] == "root_credentials_need_analyst"


def test_evidence_hashes_in_record_match_the_files(aws, invoke):
    import hashlib
    go_live(aws)
    invoke(load_event("gd-ec2-high.json", **{"i-0abc1234567890def": aws["instance"]}))
    rec = records(aws)[0]
    assert rec["finding_created_at"] == "2026-11-20T10:10:00Z"
    assert rec["evidence"], "evidence files must be listed"
    for item in rec["evidence"]:
        key = item["uri"].split("ir-evidence-bucket/", 1)[1]
        body = aws["s3"].get_object(Bucket="ir-evidence-bucket", Key=key)["Body"].read()
        assert hashlib.sha256(body).hexdigest() == item["sha256"]


def test_runbook_is_valid_and_rejects_shell_characters():
    import pathlib, re, yaml
    doc = yaml.safe_load((pathlib.Path(__file__).parents[1] / "ssm" / "IR-CollectEC2Forensics.yaml").read_text())
    assert doc["schemaVersion"] == "0.3"
    assert [s["name"] for s in doc["mainSteps"]] == ["waitForSsmAgent", "collectHashAndUpload", "tagInstance"]
    p = {k: re.compile(v["allowedPattern"]) for k, v in doc["parameters"].items()}
    assert p["FindingId"].match("a1b2c3d4e5f6") and not p["FindingId"].match("x; rm -rf /")
    assert p["InstanceId"].match("i-0abc1234567890def") and not p["InstanceId"].match("i-1 && curl evil")
    from records import safe_id
    sh_id = "arn:aws:guardduty:us-east-1:123456789012:detector/D/finding/abc"
    assert p["FindingId"].match(safe_id(sh_id))          # what the Lambda really sends is accepted


def test_access_denied_on_scope_check_is_recorded_not_raised(aws, invoke, monkeypatch):
    """Found in the real account: an SCP denied DescribeInstances and the Lambda crashed."""
    from botocore.exceptions import ClientError
    import actions
    def denied(f):
        raise ClientError({"Error": {"Code": "UnauthorizedOperation", "Message": "SCP"}}, "DescribeInstances")
    monkeypatch.setattr(actions, "resource_tags", denied)
    ev = load_event("gd-ec2-high.json")
    ev["detail"]["resource"]["instanceDetails"]["instanceId"] = aws["instance"]
    out = invoke(ev)["results"][0]
    assert out["status"] == "skipped" and out["reason"] == "scope_check_denied"
    assert "record_key" in out
