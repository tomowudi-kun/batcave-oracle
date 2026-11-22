/* STAGED ONLY: phone-friendly explicit owner review surface.
 * Mount is opt-in from existing original-origin portal. There is currently NO
 * production general-control challenge/record/decline route wired to these
 * callbacks. Callbacks must originate from the authenticated owner API, not
 * arbitrary page scripts or user-controlled challenge content.
 *
 * This panel NEVER issues a grant, dispatches a task, enrolls a signing key,
 * exports a private key, or claims that an owner signature is a release.
 */
import {
  inspectGeneralControlOwnerChallengeV1,
  signGeneralControlOwnerChallengeV1,
} from './general_control_owner_signing_v1.mjs';

const ORIGINAL_ORIGIN = 'https://batcave-linux-approval.vercel.app';
const RECEIPT_SCHEMA = 'batcave.general_control.owner_evidence_receipt.v1';
const DECLINE_SCHEMA = 'batcave.general_control.owner_decline_receipt.v1';

function mustFunction(value, name) {
  if (typeof value !== 'function') throw new Error('GENERAL_CONTROL_PHONE_' + name + '_REQUIRED');
}

function receiptFor(challenge, result, schema, state) {
  return result !== null && typeof result === 'object' && !Array.isArray(result) &&
    result.schema === schema &&
    result.owner_user_id === challenge.request.owner_user_id &&
    result.request_id === challenge.request.request_id &&
    result.nonce === challenge.request.nonce &&
    result.state === state &&
    result.execution_authorized === false &&
    result.deployment_authorized === false;
}

function detailsText(preview) {
  return [
    'Device: ' + preview.device,
    'Capability: ' + preview.capability,
    'Browser origin: ' + (preview.target_origin ?? 'Not applicable'),
    'Device/browser session: ' + preview.target_session_id,
    'Request ID: ' + preview.request_id,
    'Command SHA-256: ' + preview.command_digest,
    'Source commit: ' + preview.source_commit,
    'Policy SHA-256: ' + preview.policy_digest,
    'Rollback: ' + preview.rollback_ref,
    'Expires: ' + preview.expires_at,
    'This is only owner evidence. Independent Strict Nanny review is still required.',
  ].join('\n');
}

/** An explicit user-click UI on the original owner-key origin only.
 * prepareChallenge, recordOwnerEvidence and declineChallenge MUST be
 * authenticated, policy-enforcing server callbacks, with nonce ledger binding.
 * They are intentionally NOT implemented here; no fake success fallback.
 */
export function mountGeneralControlPhonePanelV1({
  root, doc, origin, getOwnerId, getOwnerKey,
  prepareChallenge, recordOwnerEvidence, declineChallenge,
  now = Date.now,
}) {
  if (origin !== ORIGINAL_ORIGIN) throw new Error('GENERAL_CONTROL_PHONE_WRONG_ORIGIN');
  if (!root || typeof root.append !== 'function' || !doc || typeof doc.createElement !== 'function')
    throw new Error('GENERAL_CONTROL_PHONE_DOM_REQUIRED');
  for (const [value,name] of [[getOwnerId,'GET_OWNER'],[getOwnerKey,'GET_KEY'],
    [prepareChallenge,'PREPARE_CHALLENGE'],[recordOwnerEvidence,'RECORD_EVIDENCE'],
    [declineChallenge,'DECLINE_CHALLENGE'],[now,'CLOCK']]) mustFunction(value,name);
  const section = doc.createElement('section');
  section.id = 'batcave-general-control-phone';
  const heading = doc.createElement('h2');
  heading.textContent = 'Batcave: specific computer or browser approval';
  const description = doc.createElement('p');
  description.textContent = 'Check the exact action. No grants are issued from this screen.';
  const review = doc.createElement('button');
  review.type = 'button'; review.textContent = 'Review current request';
  const yes = doc.createElement('button');
  yes.type = 'button'; yes.textContent = 'Yes — sign this exact request';
  const no = doc.createElement('button');
  no.type = 'button'; no.textContent = 'No — decline request';
  const details = doc.createElement('pre');
  details.textContent = 'No verified general-control request is loaded.';
  const status = doc.createElement('p');
  status.textContent = 'Not ready: a trusted owner challenge is required.';
  section.append(heading,description,review,details,yes,no,status);
  root.append(section);

  let phase = 'NOT_READY', challenge = null, preview = null, busy = false;
  function controls() {
    const ready = phase === 'READY';
    review.disabled = busy || phase === 'READY';
    yes.disabled = busy || !ready;
    no.disabled = busy || !ready;
  }
  function report(next, message) {
    phase=next; status.textContent=message; controls();
  }
  controls();

  review.onclick = async () => {
    if (busy || phase === 'READY') return;
    busy=true; controls();
    challenge=null; preview=null;
    details.textContent='Checking a fresh, exact-scope owner challenge…';
    try {
      const candidate=await prepareChallenge();
      const ownerId=await getOwnerId();
      const inspected=inspectGeneralControlOwnerChallengeV1(candidate,ownerId,now(),origin);
      challenge=candidate; preview=inspected;
      details.textContent=detailsText(inspected);
      report('READY','Review all fields. Yes signs only this request; No declines it.');
    } catch {
      challenge=null; preview=null;
      details.textContent='No verified request. Nothing has been signed or approved.';
      report('NOT_READY','Request unavailable or failed validation. No authority granted.');
    } finally {
      busy=false; controls();
    }
  };
  yes.onclick = async () => {
    if (busy || phase !== 'READY' || !challenge || !preview) return;
    busy=true; controls();
    const candidate=challenge;
    // Single attempt per loaded request. After any unknown transport result,
    // require fresh authoritative ledger inspection before signing anything else.
    phase='IN_PROGRESS'; controls();
    try {
      const ownerId=await getOwnerId();
      const evidence=await signGeneralControlOwnerChallengeV1({
        challenge:candidate, ownerUserId:ownerId, getOwnerKey, consent:true,
        now:now(), origin,
      });
      const response=await recordOwnerEvidence(evidence);
      if (!receiptFor(candidate,response,RECEIPT_SCHEMA,'owner_signature_recorded_only'))
        throw new Error('UNVERIFIED_OWNER_RECEIPT');
      report('AWAIT_INDEPENDENT_REVIEW',
        'Owner signature recorded. Privileged access remains HELD pending independent signed review.');
    } catch {
      report('VERIFY_BEFORE_RETRY',
        'Signature or submission NOT CONFIRMED. Check the one-use ledger before trying again.');
    } finally {
      challenge=null; preview=null; busy=false; controls();
    }
  };
  no.onclick = async () => {
    if (busy || phase !== 'READY' || !challenge || !preview) return;
    busy=true; phase='IN_PROGRESS'; controls();
    const candidate=challenge;
    try {
      const ownerId=await getOwnerId();
      const response=await declineChallenge({
        owner_user_id:ownerId,request_id:candidate.request.request_id,nonce:candidate.request.nonce,
      });
      if(!receiptFor(candidate,response,DECLINE_SCHEMA,'declined'))
        throw new Error('UNVERIFIED_DECLINE_RECEIPT');
      report('DECLINED','No recorded. This specific request cannot be reused.');
    } catch {
      report('VERIFY_BEFORE_RETRY','Decline NOT CONFIRMED. No signature was issued; verify ledger before retrying.');
    } finally {
      challenge=null; preview=null; busy=false; controls();
    }
  };
  return Object.freeze({
    section,review,yes,no,details,status,
    get phase(){return phase;},
  });
}
