"""Run ir-dispatcher on your laptop against a sample event, using your own AWS credentials.

DRY RUN is forced on unless you pass --live. Use only in the sandbox account.

  python run_local.py events/gd-ec2-high.json
  python run_local.py events/gd-ec2-high.json --live     (really contains the resource)

Set EVIDENCE_BUCKET, ISOLATION_SG_ID, SNS_TOPIC_ARN, AUTOMATION_ROLE_ARN first
(PowerShell: $env:EVIDENCE_BUCKET="ir-evidence-bucket").
"""
import argparse
import json
import logging
import os
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).parent / "lambda" / "ir_dispatcher"))
logging.basicConfig(level=logging.INFO, format="%(message)s")

ap = argparse.ArgumentParser()
ap.add_argument("event_file")
ap.add_argument("--live", action="store_true", help="actually change resources (sandbox only)")
args = ap.parse_args()

os.environ["DRY_RUN"] = "false" if args.live else "true"
if args.live and input("LIVE mode will change real resources. Type 'contain' to continue: ") != "contain":
    sys.exit("Cancelled.")

import handler  # noqa: E402  (imported after DRY_RUN is set)


class Ctx:
    aws_request_id = "local-run"


event = json.loads(pathlib.Path(args.event_file).read_text())
print(json.dumps(handler.lambda_handler(event, Ctx()), indent=2))
