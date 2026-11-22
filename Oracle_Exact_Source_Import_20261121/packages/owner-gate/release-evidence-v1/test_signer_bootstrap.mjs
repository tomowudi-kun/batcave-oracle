import test from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes} from 'node:crypto';
import {encryptPkcs8,decryptPkcs8,validateEnvelope,checkArtifacts,resolveReviewPaths} from './cortana_independent_reviewer.mjs';
import {resolve} from 'node:path';
import {spawnSync} from 'node:child_process';
import {PIN,SCHEMA} from './verify_release_approval_v1.mjs';
const now=Date.parse('2026-11-21T18:00:00.000Z');
const payload={...PIN, schema:SCHEMA,owner_user_id:'123e4567-e89b-42d3-a456-426614174000',nonce:'a'.repeat(32),issued_at:new Date(now-1000).toISOString(),expires_at:new Date(now+120000).toISOString()};
const env={schema:'batcave.oracle.gate.release.challenge.v1',issuer:'batcave-control',owner_signature_b64url:'A'.repeat(86),payload};
test('local key wrap/decrypt round-trip',()=>{const original=randomBytes(100),enc=encryptPkcs8(Buffer.from(original),'this-is-a-strong-testing-passphrase');assert.deepEqual(decryptPkcs8(enc,'this-is-a-strong-testing-passphrase'),original);});
test('rejects incorrect decryption passphrase',()=>{const enc=encryptPkcs8(randomBytes(150),'this-is-a-strong-testing-passphrase');assert.throws(()=>decryptPkcs8(enc,'wrong-other-passphrase'));});
test('rejects unauthenticated owner signature even when manifest pins match',()=>assert.throws(()=>validateEnvelope(env,now),/OWNER_SIGNATURE_INVALID/));
test('rejects missing issuer evidence',()=>assert.throws(()=>validateEnvelope({...env,issuer:'other-system'},now),/MISSING_GATE/));
test('rejects changed worker release archive',()=>assert.throws(()=>validateEnvelope({...env,payload:{...payload,worker_zip_sha256:'f'.repeat(64)}},now),/WRONG_PIN/));
test('rejects expanded arbitrary shell scope',()=>assert.throws(()=>validateEnvelope({...env,payload:{...payload,scope:'general_shell'}},now),/WRONG_PIN/));
test('rejects expired challenge',()=>assert.throws(()=>validateEnvelope(env,now+130000),/EXPIRED/));
test('rejects expanded challenge fields',()=>assert.throws(()=>validateEnvelope({...env,payload:{...payload,command:'powershell'}},now),/BAD_RELEASE_FIELDS/));
test('rejects absent artifact paths',()=>assert.throws(()=>checkArtifacts(payload,'not-a-real-path','also-not-a-path'),/ENOENT/));
test('resolves every review CLI argument without passing map indexes to path.resolve',()=>{
 const paths=['private folder','challenge.json','gate.zip','worker.zip','repo'];
 assert.deepEqual(resolveReviewPaths(paths),paths.map(p=>resolve(p)));
});
test('review CLI reaches the interactive trust boundary instead of failing on path parsing',()=>{
 const r=spawnSync(process.execPath,['cortana_independent_reviewer.mjs','review','key','challenge','gate','worker','repo'],{cwd:import.meta.dirname,encoding:'utf8'});
 assert.equal(r.status,1);assert.match(r.stderr,/HUMAN_INTERACTIVE_TTY_REQUIRED/);
 assert.doesNotMatch(r.stderr,/paths\[|Received type number/);
});
