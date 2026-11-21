#!/usr/bin/env python3
"""Batcave Linux worker POC v0.4: typed inventory, fixed build or fixed model lab.

No arbitrary cloud shell, package operations or production writes.
The old build operation remains deterministic. The new operation runs only the
SHA-pinned local agent and one fixed model-generation coding fixture in a user lab.
This is a restricted engineering acceptance, not autonomous service repair.
"""
import argparse
import subprocess
import datetime as dt
import hashlib
import hmac
import json
import os
import pathlib
import platform
import re
import sys
import uuid

SCHEMA = "batcave.linux.job.v1"
BUILD_OP = "disposable_project_build_v1"
MODEL_OP = "model_generate_and_verify_v1"
ALLOWED_OPERATIONS = frozenset(("runtime_inventory", BUILD_OP, MODEL_OP))
RECEIPT_SCHEMA = "batcave.linux.receipt.v1"
_ALLOWED_FIELDS = {"schema", "job_id", "target", "operation", "issued_at", "expires_at", "nonce", "signature"}


class Rejected(Exception):
    """A denied job; no operation is executed."""


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def digest(obj):
    return hashlib.sha256(canonical(obj)).hexdigest()


def utc_now():
    return dt.datetime.now(dt.timezone.utc)


def parse_time(value):
    if not isinstance(value, str) or not value.endswith("Z"):
        raise Rejected("timestamp must be UTC ISO8601 with trailing Z")
    try:
        parsed = dt.datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as ex:
        raise Rejected("invalid timestamp") from ex
    return parsed


def authenticate(job, key, target, now=None):
    """Fail closed: narrow operation, request shape, fresh scope, and HMAC."""
    now = now or utc_now()
    if not isinstance(job, dict) or set(job) != _ALLOWED_FIELDS:
        raise Rejected("unexpected or missing fields")
    if job.get("schema") != SCHEMA or job.get("operation") not in ALLOWED_OPERATIONS:
        raise Rejected("unsupported schema or operation")
    if job.get("target") != target or target != "BatcaveUbuntu":
        raise Rejected("target mismatch")
    try:
        uuid.UUID(job["job_id"])
    except (TypeError, ValueError, AttributeError) as ex:
        raise Rejected("job_id must be UUID") from ex
    if not isinstance(job["nonce"], str) or not re.fullmatch(r"[0-9a-f]{32}", job["nonce"]):
        raise Rejected("nonce must be 16 bytes encoded as lowercase hex")
    issued = parse_time(job["issued_at"])
    expires = parse_time(job["expires_at"])
    if issued > now + dt.timedelta(seconds=30) or expires <= now:
        raise Rejected("job not currently valid")
    if expires <= issued or (expires - issued) > dt.timedelta(minutes=10):
        raise Rejected("invalid job validity window")
    if not isinstance(job["signature"], str) or not re.fullmatch(r"[0-9a-f]{64}", job["signature"]):
        raise Rejected("invalid signature format")
    unsigned = {k: v for k, v in job.items() if k != "signature"}
    expected = hmac.new(key, canonical(unsigned), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, job["signature"]):
        raise Rejected("signature mismatch")
    return unsigned


def collect_runtime():
    """Read-only inventory; deliberate absence of arbitrary command execution."""
    return {
        "kernel": platform.release(),
        "architecture": platform.machine(),
        "python": platform.python_version(),
        "system": platform.system(),
    }


BUILD_SOURCE = '''"""Small, deterministic backoff policy for persistent task retry scheduling."""


def retry_delay(attempt: int, base: int = 2, cap: int = 60) -> int:
    """Compute bounded exponential retry seconds; attempt zero is initial retry."""
    if type(attempt) is not int or attempt < 0:
        raise ValueError("attempt must be a nonnegative integer")
    if type(base) is not int or base < 1:
        raise ValueError("base must be a positive integer")
    if type(cap) is not int or cap < 1:
        raise ValueError("cap must be a positive integer")
    return min(cap, base * (2 ** min(attempt, 30)))
'''

BUILD_TEST = '''import sys
from pathlib import Path
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from retry_policy import retry_delay

class RetryPolicyTests(unittest.TestCase):
    def test_first_delay(self): self.assertEqual(retry_delay(0), 2)
    def test_exponential(self): self.assertEqual(retry_delay(3), 16)
    def test_capped(self): self.assertEqual(retry_delay(20), 60)
    def test_custom_parameters(self): self.assertEqual(retry_delay(2, 3, 20), 12)
    def test_noninteger_denied(self):
        with self.assertRaises(ValueError): retry_delay(True)
    def test_negative_denied(self):
        with self.assertRaises(ValueError): retry_delay(-1)
'''

BUILD_README = '''# Batcave disposable code-build acceptance
This workspace was created by a typed cloud job. Its source is generated from
a fixed, audited template (not arbitrary cloud-supplied source).

`src/retry_policy.py` implements capped exponential backoff.
`tests/test_retry_policy.py` contains six unit tests.
The durable cloud receipt includes source SHA-256 and passing test count.
This is not AI-authored code; it tests the persistent build/test/report pipeline.
'''

def build_disposable_project(job_id: str, receipt_dir):
    """Create source/tests only inside a new unique lab folder; no replay."""
    root = pathlib.Path(receipt_dir).parent / 'lab-projects'
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    workspace = root / job_id
    try:
        workspace.mkdir(mode=0o700)
    except FileExistsError as ex:
        raise Rejected('disposable_workspace_exists; never replay ambiguous build') from ex
    srcdir, testdir = workspace / 'src', workspace / 'tests'
    srcdir.mkdir(mode=0o700); testdir.mkdir(mode=0o700)
    for name, data in (('src/retry_policy.py', BUILD_SOURCE),
                       ('tests/test_retry_policy.py', BUILD_TEST),
                       ('README.md', BUILD_README)):
        target = workspace / name
        with target.open('x', encoding='utf-8') as f:
            f.write(data)
            f.flush(); os.fsync(f.fileno())
    completed = subprocess.run([sys.executable, '-I', '-m', 'unittest', 'discover',
         '-s', 'tests', '-v'], cwd=str(workspace), stdin=subprocess.DEVNULL,
         capture_output=True, text=True, timeout=25, check=False,
         env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8'})
    if completed.returncode != 0 or 'Ran 6 tests' not in completed.stderr or 'OK' not in completed.stderr:
        raise Rejected('fixed_disposable_unit_tests_failed')
    source_bytes = (srcdir / 'retry_policy.py').read_bytes()
    return {'workspace': 'lab-projects/' + job_id,
            'artifact': 'src/retry_policy.py',
            'artifact_sha256': hashlib.sha256(source_bytes).hexdigest(),
            'artifact_bytes': len(source_bytes),
            'tests_passed': True, 'tests_run': 6}


def model_disposable_project(job, receipt_dir, now=None):
    """A fixed, owner-reviewed local model coding fixture; never takes prompts/paths from cloud."""
    from model_capability import TaskBlocked, load_reviewed_agent, run_typed_job
    agent_path = pathlib.Path.home() / "Downloads" / "Oracle_Local_AI_POC_v0.1" / "agent.py"
    root = pathlib.Path.home() / ".local" / "share" / "batcave-oracle-model-lab"
    try:
        agent = load_reviewed_agent(agent_path)
        result = run_typed_job({
            "id": job["job_id"],
            "nonce": job["nonce"],
            "operation": MODEL_OP,
            "expires_at": job["expires_at"],
        }, agent, root, now=now)
    except TaskBlocked as ex:
        raise Rejected("fixed_model_lab_blocked:" + str(ex)) from ex
    return result


def execute(job, key, target, receipt_dir, now=None):
    unsigned = authenticate(job, key, target, now)
    receipt_dir = pathlib.Path(receipt_dir)
    if not receipt_dir.is_dir():
        raise Rejected("receipt directory must already exist")
    # Exclusive create denies replay when the same job_id is submitted again.
    path = receipt_dir / (job["job_id"] + ".receipt.json")
    if job["operation"] == "runtime_inventory":
        result = collect_runtime()
    elif job["operation"] == BUILD_OP:
        result = build_disposable_project(job["job_id"], receipt_dir)
    elif job["operation"] == MODEL_OP:
        result = model_disposable_project(job, receipt_dir, now=now)
    else:
        raise Rejected("unexpected_unregistered_operation")
    payload = {
        "schema": RECEIPT_SCHEMA,
        "job_id": job["job_id"],
        "target": target,
        "operation": job["operation"],
        "outcome": "success",
        "completed_at": utc_now().isoformat(timespec="seconds").replace("+00:00", "Z"),
        "request_sha256": digest(unsigned),
        "result": result,
        "result_sha256": digest(result),
    }
    payload["receipt_hmac_sha256"] = hmac.new(key, canonical(payload), hashlib.sha256).hexdigest()
    # Refuse to overwrite; no changes outside the explicitly supplied receipt folder.
    try:
        with open(path, "x", encoding="utf-8") as output:
            json.dump(payload, output, sort_keys=True, indent=2)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
    except FileExistsError as ex:
        raise Rejected("replayed job: receipt already exists") from ex
    return payload


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--request", required=True, help="JSON job file")
    ap.add_argument("--receipt-dir", required=True, help="existing directory for new, exclusive receipt")
    ap.add_argument("--target", default="BatcaveUbuntu")
    args = ap.parse_args(argv)
    try:
        key_string = os.environ.get("BATCAVE_APPROVAL_KEY", "")
        if len(key_string) < 32:
            raise Rejected("approval key missing or too short")
        if len(key_string.encode("utf-8")) < 32:
            raise Rejected("approval key too short")
        key = key_string.encode("utf-8")
        with open(args.request, encoding="utf-8") as f:
            job = json.load(f)
        receipt = execute(job, key, args.target, args.receipt_dir)
        print(canonical({"job_id": receipt["job_id"], "status": "succeeded", "receipt_sha256": digest(receipt)}).decode("ascii"))
        return 0
    except (Rejected, json.JSONDecodeError, OSError) as ex:
        print("DENIED: " + str(ex), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
