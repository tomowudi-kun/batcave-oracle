#!/usr/bin/env python3
"""STAGED typed Oracle model capability. This module does not poll cloud or alter live workers.

An existing worker must supply an authenticated, leased, pre-approved job. The worker
remains responsible for device HMAC signing, receipt delivery and Strict Nanny gates.
"""
import datetime as dt
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import uuid

OPERATION = 'model_generate_and_verify_v1'
MODEL = 'qwen2.5-coder:1.5b'
NONCE = re.compile(r'^[a-f0-9]{32}$')
EXPECTED_AGENT_SHA256 = 'e60ec797966fd0055cc9c4e2cde2638599695539c8bd681b6def73ff4ab7020a'


class TaskBlocked(Exception):
    pass


def load_reviewed_agent(path):
    """Load ONLY the exact previously tested local model agent source."""
    p = Path(path).expanduser()
    if not p.is_file() or p.is_symlink():
        raise TaskBlocked('reviewed agent file missing or symlinked')
    if hashlib.sha256(p.read_bytes()).hexdigest() != EXPECTED_AGENT_SHA256:
        raise TaskBlocked('local model agent source hash differs from reviewed version')
    spec = importlib.util.spec_from_file_location('batcave_reviewed_model_agent', str(p))
    if spec is None or spec.loader is None:
        raise TaskBlocked('unable to import reviewed agent')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def parse_job(job, now=None):
    if not isinstance(job, dict) or set(job) != {'id', 'nonce', 'operation', 'expires_at'}:
        raise TaskBlocked('unexpected job fields')
    if job['operation'] != OPERATION:
        raise TaskBlocked('operation not allowlisted')
    try:
        job_id = str(uuid.UUID(job['id']))
    except (ValueError, TypeError, AttributeError) as e:
        raise TaskBlocked('invalid job id') from e
    if job_id != job['id'] or not isinstance(job['nonce'], str) or not NONCE.fullmatch(job['nonce']):
        raise TaskBlocked('invalid job id or nonce')
    if not isinstance(job['expires_at'], str):
        raise TaskBlocked('missing expiry')
    try:
        expiry = dt.datetime.fromisoformat(job['expires_at'].replace('Z', '+00:00'))
    except ValueError as e:
        raise TaskBlocked('invalid expiry') from e
    if expiry.tzinfo is None:
        raise TaskBlocked('expiry timezone required')
    now = now or dt.datetime.now(dt.timezone.utc)
    remaining = (expiry - now).total_seconds()
    if remaining <= 0 or remaining > 3600:
        raise TaskBlocked('expired or oversized lease window')
    return job_id


def _write_json_atomic(path, data):
    tmp = path.with_suffix(path.suffix + '.tmp.' + uuid.uuid4().hex)
    try:
        with open(tmp, 'x', encoding='utf-8') as f:
            os.fchmod(f.fileno(), 0o600)
            json.dump(data, f, sort_keys=True, indent=2)
            f.write('\n')
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    finally:
        if tmp.exists():
            tmp.unlink()


def run_typed_job(job, agent, root, *, now=None):
    """Execute only one fixed, safe coding fixture; return result for worker signing.

    The local model is never allowed to supply an operation, path, command or prompt.
    A previous claim with no receipt remains UNCERTAIN; it is never retried blindly.
    """
    job_id = parse_job(job, now=now)
    root = Path(root).expanduser()
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    jobs = root / 'model-job-claims'
    jobs.mkdir(mode=0o700, exist_ok=True)
    workdir = jobs / job_id
    receipt = workdir / 'result.json'
    if workdir.exists():
        if not receipt.is_file():
            raise TaskBlocked('UNCERTAIN: job already claimed without result')
        previous = json.loads(receipt.read_text(encoding='utf-8'))
        if previous.get('job_id') != job_id or previous.get('nonce') != job['nonce']:
            raise TaskBlocked('prior result belongs to another request')
        if previous.get('status') != 'LAB_PASS':
            raise TaskBlocked('prior model attempt failed; no automatic replay')
        return previous['result']
    # Directory creation acts as an exclusive, persistent create-only claim.
    workdir.mkdir(mode=0o700)
    _write_json_atomic(workdir / 'claim.json', {'job_id': job_id, 'nonce': job['nonce'], 'operation': OPERATION})
    # Integration must separately verify the installed agent's exact source hash.
    if not hasattr(agent, 'run_once'):
        raise TaskBlocked('reviewed local model agent missing')
    lab = agent.run_once(MODEL, 'http://127.0.0.1:11434', root)
    if lab.get('status') != 'LAB_PASS' or lab.get('tests_run') != 8 or lab.get('tests_passed') is not True:
        raise TaskBlocked('local model tests failed; claim fenced for review')
    source_path = Path(lab['artifact'])
    expected_root = root.resolve() / 'runs'
    if not source_path.is_file() or not source_path.resolve().is_relative_to(expected_root):
        raise TaskBlocked('local artifact escaped model lab')
    source = source_path.read_bytes()
    sha = hashlib.sha256(source).hexdigest()
    if sha != lab.get('artifact_sha256') or not 20 <= len(source) <= 2049:
        raise TaskBlocked('local artifact hash or length mismatch')
    # Read-only artifact copying into a disposable, job-addressed workspace.
    project = root / 'lab-projects' / job_id
    src = project / 'src'
    src.mkdir(parents=True, mode=0o700, exist_ok=False)
    dst = src / 'model_generated.py'
    with open(dst, 'xb') as f:
        os.fchmod(f.fileno(), 0o600)
        f.write(source)
        f.flush()
        os.fsync(f.fileno())
    result = {
        'workspace': f'lab-projects/{job_id}',
        'artifact': 'src/model_generated.py',
        'artifact_sha256': sha,
        'artifact_bytes': len(source),
        'tests_passed': True,
        'tests_run': 8,
        'model': MODEL,
        'local_run_id': lab['run_id'],
    }
    _write_json_atomic(receipt, {'job_id': job_id, 'nonce': job['nonce'], 'status': 'LAB_PASS', 'result': result})
    return result
