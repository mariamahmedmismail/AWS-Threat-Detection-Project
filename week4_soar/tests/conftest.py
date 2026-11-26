"""Test setup: a fake AWS account (moto) with sandbox resources for every scenario."""
import json
import os
import pathlib
import sys

import boto3
import pytest
from moto import mock_aws

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lambda" / "ir_dispatcher"))

REGION = "us-east-1"


def load_event(name: str, **replace) -> dict:
    text = (ROOT / "events" / name).read_text()
    for old, new in replace.items():
        text = text.replace(old, new)
    return json.loads(text)


@pytest.fixture
def aws(monkeypatch):
    for k, v in {"AWS_ACCESS_KEY_ID": "testing", "AWS_SECRET_ACCESS_KEY": "testing",
                 "AWS_DEFAULT_REGION": REGION}.items():
        monkeypatch.setenv(k, v)
    with mock_aws():
        import aws as aws_mod
        aws_mod.reset_clients()
        yield _build_env(monkeypatch)
        aws_mod.reset_clients()


def _build_env(monkeypatch) -> dict:
    ec2 = boto3.client("ec2", region_name=REGION)
    s3 = boto3.client("s3", region_name=REGION)
    iam = boto3.client("iam")
    sns = boto3.client("sns", region_name=REGION)

    vpc = ec2.describe_vpcs()["Vpcs"][0]["VpcId"]
    web_sg = ec2.create_security_group(GroupName="web", Description="web", VpcId=vpc)["GroupId"]
    iso_sg = ec2.create_security_group(GroupName="ir-isolation", Description="isolation", VpcId=vpc)["GroupId"]
    ami = ec2.describe_images()["Images"][0]["ImageId"]

    iam.create_role(RoleName="ec2-app-role", Path="/ec2/", Tags=[{"Key": "env", "Value": "sandbox"}],
                    AssumeRolePolicyDocument=json.dumps({
        "Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"},
                                                "Action": "sts:AssumeRole"}]}))
    iam.create_instance_profile(InstanceProfileName="ec2-app-profile")
    iam.add_role_to_instance_profile(InstanceProfileName="ec2-app-profile", RoleName="ec2-app-role")

    def instance(tags):
        return ec2.run_instances(ImageId=ami, MinCount=1, MaxCount=1, SecurityGroupIds=[web_sg],
                                 IamInstanceProfile={"Name": "ec2-app-profile"},
                                 TagSpecifications=[{"ResourceType": "instance",
                                                     "Tags": [{"Key": k, "Value": v} for k, v in tags.items()]}]
                                 )["Instances"][0]["InstanceId"]

    sandbox_instance = instance({"env": "sandbox"})
    prod_instance = instance({"env": "prod"})

    iam.create_user(UserName="backup", Tags=[{"Key": "env", "Value": "sandbox"}])
    key_id = iam.create_access_key(UserName="backup")["AccessKey"]["AccessKeyId"]
    iam.create_user(UserName="admin-user", Tags=[{"Key": "env", "Value": "sandbox"}])
    admin_key = iam.create_access_key(UserName="admin-user")["AccessKey"]["AccessKeyId"]

    s3.create_bucket(Bucket="ir-evidence-bucket")
    s3.create_bucket(Bucket="ir-sandbox-public-bucket")
    s3.put_bucket_tagging(Bucket="ir-sandbox-public-bucket",
                          Tagging={"TagSet": [{"Key": "env", "Value": "sandbox"}, {"Key": "owner", "Value": "member5"}]})
    topic = sns.create_topic(Name="ir-alerts")["TopicArn"]

    env = {"EVIDENCE_BUCKET": "ir-evidence-bucket", "ISOLATION_SG_ID": iso_sg, "SNS_TOPIC_ARN": topic,
           "AUTOMATION_ROLE_ARN": "arn:aws:iam::123456789012:role/ir-forensics-automation-role",
           "DRY_RUN": "true", "REQUIRE_SANDBOX_TAG": "true", "ALLOW_SAMPLE_FINDINGS": "false"}
    for k, v in env.items():
        monkeypatch.setenv(k, v)

    return {"ec2": ec2, "s3": s3, "iam": iam, "instance": sandbox_instance, "prod_instance": prod_instance,
            "web_sg": web_sg, "iso_sg": iso_sg, "key_id": key_id, "admin_key": admin_key,
            "vpc": vpc, "ami": ami, "monkeypatch": monkeypatch}


@pytest.fixture
def invoke():
    import handler

    class Ctx:
        aws_request_id = "test-request"

    return lambda event: handler.lambda_handler(event, Ctx())
