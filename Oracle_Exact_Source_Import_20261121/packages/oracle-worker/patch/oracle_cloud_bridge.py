#!/usr/bin/env python3
"""Oracle cloud bridge: inventory, fixed build or fixed model coding fixture.

No arbitrary remote shell, cloud-supplied prompts, SSH keys or broad cloud keys.
The local worker may call the separately reviewed, fixed model lab fixture.
"""
import datetime as dt
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import sys
import tempfile
import time
import urllib.error
import urllib.request
import uuid

BASE = Path.home() / '.local' / 'share' / 'batcave-worker'
CLOUD = BASE / 'cloud-pending'
RECEIPTS = BASE / 'receipts'
INBOX = BASE / 'inbox'
KEYFILE = BASE / 'approval_key'
TOKENFILE = Path.home() / '.config' / 'batcave-oracle' / 'device-token'
URL = 'https://wizflveeptzeajsdybzs.supabase.co/functions/v1/batcave-oracle-bridge-v1'
SCHEMA = 'batcave.oracle.job.v1'
BUILD_POLL_OP = 'poll_model'  # capability handshake; old poll_build never claims model jobs

sys.path.insert(0, str(BASE))
from batcave_linux_worker import canonical  # existing installed local worker v0.2


def utcnow():
    return dt.datetime.now(dt.timezone.utc)


def format_utc(x):
    return x.astimezone(dt.timezone.utc).isoformat(timespec='seconds').replace('+00:00', 'Z')


def atomic_json(path, obj):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    tmp = path.with_name(path.name + '.' + secrets.token_hex(5) + '.tmp')
    with tmp.open('x', encoding='utf-8') as out:
        json.dump(obj, out, sort_keys=True, indent=2)
        out.write('\n')
        out.flush(); os.fsync(out.fileno())
    os.replace(tmp, path)


def request(token, body):
    data = canonical(body)
    if len(data) > 6000:
        raise ValueError('request_too_large')
    req = urllib.request.Request(URL, data=data, headers={
        'content-type': 'application/json',
        'x-batcave-device-token': token,
        'user-agent': 'Batcave-Oracle-InventoryBridge/0.1',
    }, method='POST')
    with urllib.request.urlopen(req, timeout=12) as resp:
        if resp.status != 200:
            raise RuntimeError('unexpected_http_' + str(resp.status))
        payload = resp.read(8000)
    value = json.loads(payload.decode('utf-8'))
    if not isinstance(value, dict) or not value.get('ok') or value.get('scope') != 'oracle_runtime_inventory_v1':
        raise ValueError('unexpected_cloud_response')
    return value


def validate_cloud_job(item):
    if not isinstance(item, dict) or set(item) != {'id', 'nonce', 'expires_at', 'operation'}:
        raise ValueError('unexpected_job_shape')
    ident = str(uuid.UUID(item['id']))
    if ident != item['id']:
        raise ValueError('invalid_job_uuid')
    if item['operation'] not in ('runtime_inventory', 'disposable_project_build_v1',
                                  'model_generate_and_verify_v1'):
        raise ValueError('unauthorized_operation')
    nonce = item['nonce']
    if not isinstance(nonce, str) or len(nonce) != 32 or any(c not in '0123456789abcdef' for c in nonce):
        raise ValueError('nonce_invalid')
    exp = dt.datetime.fromisoformat(item['expires_at'].replace('Z', '+00:00'))
    if exp.tzinfo is None or exp <= utcnow():
        raise ValueError('job_expired')
    return exp


def make_local_request(job, key):
    exp = validate_cloud_job(job)
    now = utcnow()
    deadline = min(exp, now + dt.timedelta(minutes=4))
    if deadline <= now + dt.timedelta(seconds=5):
        raise ValueError('job_expiring')
    unsigned = {
        'schema': 'batcave.linux.job.v1',
        'job_id': job['id'], 'target': 'BatcaveUbuntu',
        'operation': job['operation'],
        'issued_at': format_utc(now), 'expires_at': format_utc(deadline),
        'nonce': job['nonce'],
    }
    unsigned['signature'] = hmac.new(key, canonical(unsigned), hashlib.sha256).hexdigest()
    return unsigned


def verified_receipt(job, key):
    dest = RECEIPTS / (job['id'] + '.receipt.json')
    if not dest.is_file():
        return None
    receipt = json.loads(dest.read_text(encoding='utf-8'))
    if not isinstance(receipt, dict):
        raise ValueError('receipt_not_object')
    signature = receipt.get('receipt_hmac_sha256')
    if not isinstance(signature, str) or len(signature) != 64:
        raise ValueError('receipt_hmac_invalid')
    signed = {k: v for k, v in receipt.items() if k != 'receipt_hmac_sha256'}
    actual = hmac.new(key, canonical(signed), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(actual, signature):
        raise ValueError('receipt_hmac_mismatch')
    if receipt.get('job_id') != job['id'] or receipt.get('operation') != job['operation'] or receipt.get('target') != 'BatcaveUbuntu' or receipt.get('outcome') != 'success':
        raise ValueError('receipt_scope_mismatch')
    if job['operation'] == 'disposable_project_build_v1':
        result = receipt.get('result')
        if not isinstance(result, dict) or result.get('tests_passed') is not True or result.get('tests_run') != 6:
            raise ValueError('build_tests_missing_or_failed')
        value = result.get('artifact_sha256')
        if not isinstance(value, str) or len(value) != 64 or any(c not in '0123456789abcdef' for c in value):
            raise ValueError('artifact_hash_invalid')
        if result.get('workspace') != 'lab-projects/' + job['id']:
            raise ValueError('build_workspace_mismatch')
    elif job['operation'] == 'model_generate_and_verify_v1':
        result = receipt.get('result')
        if not isinstance(result, dict) or set(result) != {
            'workspace', 'artifact', 'artifact_sha256', 'artifact_bytes',
            'tests_passed', 'tests_run', 'model', 'local_run_id'}:
            raise ValueError('model_result_shape_invalid')
        if result.get('tests_passed') is not True or type(result.get('tests_run')) is not int or result['tests_run'] != 8:
            raise ValueError('model_tests_missing_or_failed')
        if result.get('workspace') != 'lab-projects/' + job['id'] or result.get('artifact') != 'src/model_generated.py':
            raise ValueError('model_artifact_scope_mismatch')
        if result.get('model') != 'qwen2.5-coder:1.5b':
            raise ValueError('model_id_not_reviewed')
        try:
            if str(uuid.UUID(result['local_run_id'])) != result['local_run_id']:
                raise ValueError('model_run_id_invalid')
        except (TypeError, ValueError, AttributeError) as ex:
            raise ValueError('model_run_id_invalid') from ex
        if not isinstance(result.get('artifact_sha256'), str) or len(result['artifact_sha256']) != 64 or any(c not in '0123456789abcdef' for c in result['artifact_sha256']):
            raise ValueError('model_artifact_digest_invalid')
        if type(result.get('artifact_bytes')) is not int or not 20 <= result['artifact_bytes'] <= 2049:
            raise ValueError('model_artifact_size_invalid')
        # Independently read fixed local artifact; do not trust model-returned hash alone.
        artifact = (Path.home() / '.local/share/batcave-oracle-model-lab' /
                    'lab-projects' / job['id'] / 'src/model_generated.py')
        if artifact.is_symlink() or not artifact.is_file() or artifact.stat().st_size != result['artifact_bytes']:
            raise ValueError('local_model_artifact_missing')
        if hashlib.sha256(artifact.read_bytes()).hexdigest() != result['artifact_sha256']:
            raise ValueError('local_model_artifact_hash_mismatch')
    return receipt


def deliver_or_resume(job, key):
    local = RECEIPTS / (job['id'] + '.receipt.json')
    if local.is_file():
        return
    matches = [BASE / d / (job['id'] + '.json') for d in ('inbox', 'claimed', 'done', 'rejected')]
    if any(path.exists() for path in matches):
        # A pending or claimed job can still complete. Never replay ambiguous work.
        return
    request_obj = make_local_request(job, key)
    atomic_json(INBOX / (job['id'] + '.json'), request_obj)


def drain_receipts(token, key):
    for path in sorted(CLOUD.glob('*.json')):
        job = json.loads(path.read_text(encoding='utf-8'))
        receipt = verified_receipt(job, key)
        if receipt is None:
            continue
        response = request(token, {'op': 'receipt', 'command_id': job['id'],
                                  'nonce': job['nonce'], 'result': receipt})
        if response.get('receipt') in ('recorded', 'already_recorded'):
            path.unlink()
            print('ORACLE_CLOUD_RECEIPT_ACK=' + job['id'], flush=True)
        else:
            raise ValueError('receipt_unacknowledged')


def main():
    os.umask(0o077)
    for path in (BASE, CLOUD, RECEIPTS, INBOX):
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
    token = TOKENFILE.read_text(encoding='ascii').strip()
    if len(token) != 64 or any(c not in '0123456789abcdef' for c in token):
        raise ValueError('device_token_format')
    key = KEYFILE.read_text(encoding='utf-8').strip().encode('utf-8')
    if len(key) < 32:
        raise ValueError('local_approval_key_missing')
    print('ORACLE_CLOUD_BRIDGE_STARTED', flush=True)
    while True:
        try:
            drain_receipts(token, key)
            data = request(token, {'op':BUILD_POLL_OP})
            if data.get('pending') is True:
                job = data.get('job')
                validate_cloud_job(job)
                state = CLOUD / (job['id'] + '.json')
                if not state.exists():
                    atomic_json(state, job)
                deliver_or_resume(job, key)
        except (urllib.error.URLError, TimeoutError, ValueError, OSError, RuntimeError, json.JSONDecodeError) as exc:
            # Never log credentials or full responses.
            print('ORACLE_BRIDGE_RETRY_REASON=' + type(exc).__name__, flush=True)
        time.sleep(8)

if __name__ == '__main__':
    main()
