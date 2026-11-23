// Staged, NON-AUTHORIZING public candidate intake. This never registers,
// attests, promotes or approves a reviewer. No private material is accepted.
import {createHash} from 'node:crypto';
const FIELDS=['schema','purpose','device','account','sid','public_key_spki_der_b64','public_key_sha256','independently_attested','production_authorized'];
const B64=/^[A-Za-z0-9+/]+={0,2}$/;
const HEX=/^[a-f0-9]{64}$/;
function deny(reason){throw new Error('REVIEWER_CANDIDATE_'+reason)}
export function parsePublicReviewerCandidateV1(input, trusted) {
  if(typeof input!=='string'||input.length>4096)deny('INPUT');
  let c;try{c=JSON.parse(input)}catch{deny('JSON')}
  if(!c||typeof c!=='object'||Array.isArray(c)||Object.keys(c).length!==FIELDS.length||
    !FIELDS.every(k=>Object.hasOwn(c,k)))deny('FIELDS');
  if(!trusted||typeof trusted!=='object'||!['account','sid','device'].every(k=>typeof trusted[k]==='string'))deny('TRUST');
  if(c.schema!=='batcave.general_control.reviewer_candidate.v1'||c.purpose!=='general_control_privileged_reviewer')deny('PURPOSE');
  if(c.device!=='Cortana'||c.device!==trusted.device||c.account!==trusted.account||c.sid!==trusted.sid)deny('CUSTODY');
  if(c.independently_attested!==false||c.production_authorized!==false)deny('CLAIMED_AUTHORITY');
  if(typeof c.public_key_spki_der_b64!=='string'||!B64.test(c.public_key_spki_der_b64)||
    c.public_key_spki_der_b64.length>512||!HEX.test(c.public_key_sha256))deny('PUBLIC_KEY');
  const bytes=Buffer.from(c.public_key_spki_der_b64,'base64');
  if(bytes.toString('base64')!==c.public_key_spki_der_b64||
     bytes.length!==44||bytes.subarray(0,12).toString('hex')!=='302a300506032b6570032100')deny('ED25519_SPKI');
  // Cryptographic digest equality is verified before recording candidate.
  // This is a PUBLIC key fingerprint only, not proof of key possession.
  if(createHash('sha256').update(bytes).digest('hex')!==c.public_key_sha256)deny('FINGERPRINT');
  return Object.freeze({public_key_sha256:c.public_key_sha256,public_key_spki_der_b64:c.public_key_spki_der_b64,account:c.account,sid:c.sid,device:c.device,independently_attested:false,production_authorized:false,execution_authorized:false});
}
