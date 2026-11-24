// Oracle_Exact_Source_Import_20261121/packages/owner-gate/candidate-possession-v1/test_http_boundary_and_repo_failures_STAGED.mjs
// STAGED offline regression suite for PR #3 commit 40a48a041b8fa0f8bb84f4459edbd244dff7148e.
// Non-duplicative of test_handler_STAGED.mjs and test_general_control_reviewer_possession_STAGED.mjs.
// Synthetic ephemeral Ed25519 keys only. Zero live DB, network, secrets, or deployment actions.

import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, createHash, sign } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

import {
  handleCandidatePossessionOnlySTAGED as handle,
  OWNER_ID,
  DRAFT_ID,
} from './handler_STAGED.mjs';
import { possessionMessage } from '../src/general_control_reviewer_possession_STAGED.mjs';
import { makeCandidatePossessionPrivateRepoSTAGED } from '../release-evidence-v1/general_control_candidate_possession_private_repo_STAGED.mjs';

const NOW = Date.parse('2026-11-23T21:29:00.000Z');
const keys = generateKeyPairSync('ed25519');
const rawPub = keys.publicKey.export({ type: 'spki', format: 'der' }).subarray(-32);
const pubSha256 = createHash('sha256').update(rawPub).digest('hex');
const pubB64Url = rawPub.toString('base64url');

const OWNER_SESSION = { authenticated_owner: true, owner_user_id: OWNER_ID };

const VALID_CANDIDATE = {
  id: DRAFT_ID,
  owner_user_id: OWNER_ID,
  kind: 'general_control_public_reviewer_candidate_v1',
  host: 'Cortana',
  account: 'CORTANA\\StrictNannyRelease',
  sid: 'S-1-5-21-349890097-2052580754-4142396749-1004',
  public_key_sha256_raw: pubSha256,
  public_key_b64url_raw: pubB64Url,
  registered: false,
  independently_attested: false,
  production_release_authorized: false,
  execution_authorized: false,
};

function assertNoAuthority(res) {
  assert.equal(Object.isFrozen(res), true, 'response must be frozen');
  for (const field of [
    'registered',
    'independently_attested',
    'production_release_authorized',
    'execution_authorized',
    'deployment_authorized',
    'grant_issued',
  ]) {
    assert.equal(res[field], false, `authority flag ${field} must be false`);
  }
}

function makeFakeSql(responder) {
  const calls = [];
  const sql = async (strings, ...values) => {
    const query = strings.join('?').replace(/\s+/g, ' ').trim();
    calls.push({ query, values });
    return responder(query, values);
  };
  sql.json = (v) => JSON.stringify(v);
  return { sql, calls };
}

function makeHandlerFixture({ overrides = {} } = {}) {
  const state = {
    prepared: null,
    recorded: 0,
    reserveMode: 'ok', // 'ok' | 'false' | 'bad_id' | 'bad_nonce' | 'throw'
    getPreparedMode: 'ok', // 'ok' | 'throw'
    recordMode: 'ok', // 'ok' | 'false' | 'bad_state' | 'bad_id' | 'throw'
  };

  const repository = {
    async reserve(payload, signing_sha256) {
      if (state.reserveMode === 'throw') throw new Error('db_reserve_down');
      if (state.reserveMode === 'false') return { reserved: false };
      if (state.reserveMode === 'bad_id') {
        return { reserved: true, request_id: '00000000-0000-4000-8000-000000000000', nonce: payload.nonce };
      }
      if (state.reserveMode === 'bad_nonce') {
        return { reserved: true, request_id: payload.request_id, nonce: 'f'.repeat(32) };
      }
      if (state.prepared) return { reserved: false };
      state.prepared = { payload, signing_sha256, state: 'unused' };
      return { reserved: true, request_id: payload.request_id, nonce: payload.nonce };
    },
    async getPrepared(id, nonce) {
      if (state.getPreparedMode === 'throw') throw new Error('db_read_down');
      return state.prepared?.payload.request_id === id && state.prepared.payload.nonce === nonce
        ? structuredClone(state.prepared)
        : null;
    },
    async recordProof(p) {
      if (state.recordMode === 'throw') throw new Error('db_record_down');
      if (state.recordMode === 'false') return { recorded: false };
      if (state.recordMode === 'bad_state') {
        return { recorded: true, request_id: p.request_id, state: 'execution_authorized' };
      }
      if (state.recordMode === 'bad_id') {
        return { recorded: true, request_id: '00000000-0000-4000-8000-000000000000', state: 'candidate_possession_recorded_only' };
      }
      // Simulated in-memory CAS (does NOT prove live PostgreSQL row-lock atomicity)
      if (
        state.prepared?.state !== 'unused' ||
        state.prepared.payload.request_id !== p.request_id ||
        state.prepared.payload.nonce !== p.nonce
      ) {
        return { recorded: false };
      }
      state.prepared.state = 'candidate_possession_recorded_only';
      state.recorded += 1;
      return {
        recorded: true,
        request_id: p.request_id,
        state: 'candidate_possession_recorded_only',
      };
    },
    ...overrides,
  };

  const services = {
    repository,
    getPrivateCandidate: async () => ({ ...VALID_CANDIDATE }),
  };

  return { state, services };
}

function signChallenge(challenge, now = NOW) {
  return {
    schema: 'batcave.general_control.reviewer_possession_proof.v1',
    request_id: challenge.request_id,
    nonce: challenge.nonce,
    signature_hex: sign(null, Buffer.from(possessionMessage(challenge, now)), keys.privateKey).toString('hex'),
  };
}

test('REPO-1: private Postgres adapter enforces constructor/field guards, canonicalizes exact double-backslash account, and fails closed on empty/false SQL results', async () => {
  assert.throws(() => makeCandidatePossessionPrivateRepoSTAGED(null), /PRIVATE_POSTGRES_REQUIRED/);
  assert.throws(() => makeCandidatePossessionPrivateRepoSTAGED(() => {}), /PRIVATE_POSTGRES_REQUIRED/);

  const { sql, calls } = makeFakeSql((query) => {
    if (query.startsWith('INSERT INTO batcave.general_control_reviewer_possession_staged_v1')) return [];
    if (query.startsWith('SELECT batcave.general_control_record_candidate_possession_staged_v1')) {
      return [{ recorded: false }];
    }
    if (query.startsWith('SELECT id,owner_user_id,source,state,execution_authorized')) {
      return [
        {
          id: DRAFT_ID,
          owner_user_id: OWNER_ID,
          source: 'portal',
          state: 'draft',
          execution_authorized: false,
          interpreted_intent: {
            kind: 'general_control_public_reviewer_candidate_v1',
            registered: false,
            independently_attested: false,
            production_release_authorized: false,
            execution_authorized: false,
            device: 'Cortana',
            account: String.raw`CORTANA\\StrictNannyRelease`,
            sid_from_owner_screenshot: 'S-1-5-21-349890097-2052580754-4142396749-1004',
            public_key_sha256_raw: pubSha256,
            public_key_b64url_raw: pubB64Url,
          },
        },
      ];
    }
    return [];
  });

  const { repository, getPrivateCandidate } = makeCandidatePossessionPrivateRepoSTAGED(sql);

  // Field validation rejects malformed UUID/hex BEFORE touching SQL
  await assert.rejects(() => repository.getPrepared('not-a-uuid', 'a'.repeat(32)), /INVALID_PRIVATE_CANDIDATE_FIELD/);
  await assert.rejects(() => repository.getPrepared(DRAFT_ID, 'BADHEX'), /INVALID_PRIVATE_CANDIDATE_FIELD/);
  await assert.rejects(() => getPrivateCandidate('bad', OWNER_ID), /INVALID_PRIVATE_CANDIDATE_FIELD/);
  assert.equal(calls.length, 0, 'invalid fields must fail before any SQL call');

  // Empty INSERT returns {reserved: false}
  const resReserve = await repository.reserve(
    {
      request_id: 'c1b7634c-eb00-4aee-8fd5-f33bc8c96b9f',
      draft_id: DRAFT_ID,
      owner_user_id: OWNER_ID,
      nonce: 'a'.repeat(32),
      candidate_key_sha256: pubSha256,
      candidate_public_b64url: pubB64Url,
      issued_at: new Date(NOW).toISOString(),
      expires_at: new Date(NOW + 300000).toISOString(),
    },
    'b'.repeat(64)
  );
  assert.deepEqual(resReserve, { reserved: false });

  // SQL returning recorded:false maps to {recorded: false}
  const resRecord = await repository.recordProof({
    request_id: 'c1b7634c-eb00-4aee-8fd5-f33bc8c96b9f',
    draft_id: DRAFT_ID,
    owner_user_id: OWNER_ID,
    nonce: 'a'.repeat(32),
    candidate_key_sha256: pubSha256,
    signing_sha256: 'b'.repeat(64),
    signature_hex: 'c'.repeat(128),
  });
  assert.deepEqual(resRecord, { recorded: false });

  // Exact double-backslash canonicalization preserves false flags
  const cand = await getPrivateCandidate(DRAFT_ID, OWNER_ID);
  assert.equal(cand.account, String.raw`CORTANA\StrictNannyRelease`);
  assert.equal(cand.registered, false);
  assert.equal(cand.independently_attested, false);
  assert.equal(cand.production_release_authorized, false);
  assert.equal(cand.execution_authorized, false);

  // Non-draft or execution_authorized:true row returns null
  const { sql: badDraftSql } = makeFakeSql(() => [
    { id: DRAFT_ID, owner_user_id: OWNER_ID, state: 'approved', execution_authorized: false, interpreted_intent: {} },
  ]);
  const badRepo = makeCandidatePossessionPrivateRepoSTAGED(badDraftSql);
  assert.equal(await badRepo.getPrivateCandidate(DRAFT_ID, OWNER_ID), null);
});

test('HANDLER-REPO-2: reserve(), getPrepared(), and recordProof() failures, tampered receipts, and throws fail closed with zero authority', async () => {
  // 2a. reserve() failure modes on op:'issue'
  for (const [mode, expectedReason] of [
    ['false', 'PRIVATE_NONCE_RESERVATION_REQUIRED'],
    ['bad_id', 'PRIVATE_NONCE_RESERVATION_REQUIRED'],
    ['bad_nonce', 'PRIVATE_NONCE_RESERVATION_REQUIRED'],
    ['throw', 'CHALLENGE_NOT_ISSUED'],
  ]) {
    const f = makeHandlerFixture();
    f.state.reserveMode = mode;
    const res = await handle({ op: 'issue', draft_id: DRAFT_ID }, OWNER_SESSION, f.services, NOW);
    assert.equal(res.status, 'DENY', `reserveMode=${mode} must deny`);
    assert.equal(res.reason, expectedReason);
    assertNoAuthority(res);
  }

  // 2b. getPrepared() throwing during op:'record'
  {
    const f = makeHandlerFixture();
    const issued = await handle({ op: 'issue', draft_id: DRAFT_ID }, OWNER_SESSION, f.services, NOW);
    const proof = signChallenge(issued.challenge);
    f.state.getPreparedMode = 'throw';
    const res = await handle({ op: 'record', proof }, OWNER_SESSION, f.services, NOW);
    assert.equal(res.status, 'DENY');
    assert.equal(res.reason, 'PROOF_UNAVAILABLE');
    assertNoAuthority(res);
    assert.equal(f.state.recorded, 0);
  }

  // 2c. recordProof() failure / tampered receipt / throw during op:'record'
  for (const [mode, expectedReason] of [
    ['false', 'NO_DURABLE_ONE_USE_RECEIPT'],
    ['bad_state', 'NO_DURABLE_ONE_USE_RECEIPT'],
    ['bad_id', 'NO_DURABLE_ONE_USE_RECEIPT'],
    ['throw', 'PROOF_NOT_RECORDED'],
  ]) {
    const f = makeHandlerFixture();
    const issued = await handle({ op: 'issue', draft_id: DRAFT_ID }, OWNER_SESSION, f.services, NOW);
    const proof = signChallenge(issued.challenge);
    f.state.recordMode = mode;
    const res = await handle({ op: 'record', proof }, OWNER_SESSION, f.services, NOW);
    assert.equal(res.status, 'DENY', `recordMode=${mode} must deny`);
    assert.equal(res.reason, expectedReason);
    assertNoAuthority(res);
    assert.equal(f.state.recorded, 0);
  }
});

test('CONCURRENCY-3: simulated in-memory atomic CAS rejects concurrent duplicate op:record via Promise.all', async () => {
  const f = makeHandlerFixture();
  const issued = await handle({ op: 'issue', draft_id: DRAFT_ID }, OWNER_SESSION, f.services, NOW);
  assert.equal(issued.status, 'AWAIT_EXPLICIT_KEY_POSSESSION_PROOF');
  const proof = signChallenge(issued.challenge);

  const [r1, r2] = await Promise.all([
    handle({ op: 'record', proof }, OWNER_SESSION, f.services, NOW),
    handle({ op: 'record', proof }, OWNER_SESSION, f.services, NOW),
  ]);

  assert.deepEqual([r1.status, r2.status].sort(), ['CANDIDATE_POSSESSION_RECORDED_ONLY', 'DENY']);
  assertNoAuthority(r1);
  assertNoAuthority(r2);
  assert.equal(f.state.recorded, 1);
});

test('CLOCK-4: exact 5-minute expiry boundary, future-issued skew, and non-integer clock all fail closed', async () => {
  const f = makeHandlerFixture();
  const issued = await handle({ op: 'issue', draft_id: DRAFT_ID }, OWNER_SESSION, f.services, NOW);
  const proof = signChallenge(issued.challenge);

  // Exact expiry boundary (expires_at === now -> expires_at <= now must deny)
  const atBoundary = await handle({ op: 'record', proof }, OWNER_SESSION, f.services, NOW + 300_000);
  assert.equal(atBoundary.status, 'DENY');
  assertNoAuthority(atBoundary);

  // Clock > 30s before issued_at (issued_at > now + 30000 must deny)
  const beforeSkew = await handle({ op: 'record', proof }, OWNER_SESSION, f.services, NOW - 30_001);
  assert.equal(beforeSkew.status, 'DENY');
  assertNoAuthority(beforeSkew);

  // Non-integer / NaN clock on issue and record
  const badClockRecord = await handle({ op: 'record', proof }, OWNER_SESSION, f.services, Number.NaN);
  assert.equal(badClockRecord.status, 'DENY');
  assertNoAuthority(badClockRecord);

  const fIssue = makeHandlerFixture();
  const badClockIssue = await handle({ op: 'issue', draft_id: DRAFT_ID }, OWNER_SESSION, fIssue.services, Number.NaN);
  assert.equal(badClockIssue.status, 'DENY');
  assertNoAuthority(badClockIssue);
  assert.equal(f.state.recorded, 0);
});

test('EDGE-CONTRACT-5: static source verification of candidate-possession-v1/index.ts HTTP & auth boundary (Deno runtime not executed here)', () => {
  const dir = path.dirname(fileURLToPath(import.meta.url));
  const src = readFileSync(path.join(dir, 'index.ts'), 'utf8');

  assert.match(src, /const ORIGIN='https:\/\/batcave-linux-approval\.vercel\.app';/);
  assert.match(src, /if\(origin!==ORIGIN\)return reply\(\{status:'DENY',reason:'ORIGIN_DENIED'\},403\);/);
  assert.match(src, /if\(req\.method==='OPTIONS'\)return new Response\(null,\{status:204/);
  assert.match(src, /reason:'POST_JSON_REQUIRED'\},405\);/);
  assert.match(src, /if\(raw\.length>3000\)return reply\(\{status:'DENY',reason:'REQUEST_TOO_LARGE'\},400\);/);
  assert.match(src, /withSupabase\(\{auth:'user'\}/);
  assert.match(src, /ctx\.userClaims\?\.id!==OWNER_ID/);
  assert.match(src, /!user\.email_confirmed_at/);
  assert.match(src, /registered:false,independently_attested:false/);
  assert.match(src, /execution_authorized:false/);
  assert.match(src, /deployment_authorized:false,grant_issued:false/);
});
