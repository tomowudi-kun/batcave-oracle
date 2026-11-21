/* Oracle lab-only review verification for inclusion in existing Batcave gate.
 * Pure verifier. No DB writes, dispatch, enrollment, or production authority.
 */
const DOMAIN = 'batcave.nanny.lab.review.v1\n';
const SCHEMA = 'batcave.nanny.lab.request.v1';
const RECEIPT_SCHEMA = 'batcave.nanny.lab.receipt.v1';
const JOB_SCHEMA = 'batcave.oracle.job.v1';
const FIXTURE = 'fixed_clamp_score_v1';
const OP = 'model_generate_and_verify_v1';
const ARTIFACT = '4958ee7d9847c43dc9a66e477d8db2cb75392f4c93a97aa1be5d8c4fc989747f';
const TRUSTED_CORTANA_KEY_SHA = '4133fdbf40cb94461a1c2d0f2cd1f9f9e6484693e04f2ffa03bcd9cbc53a1b8b';
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const H32 = /^[a-f0-9]{32}$/;
const H64 = /^[a-f0-9]{64}$/;
const REQ_KEYS = ['artifact_sha256','created_at','device','expires_at','nonce','operation','request_id','schema','scope'];
const RECEIPT_KEYS = ['decision','deployment_authorized','execution_authorized','host','production_release_authorized','reason','request_id','request_sha256','reviewed_at','reviewer_sid','schema'];
const PUB_KEYS = ['cloud_enrolled','host','production_release_authorized','public_key_pem','public_key_sha256','reviewer_sid','role','schema'];
const ENVELOPE_KEYS = ['payload','signature_b64url'];
const encoder = new TextEncoder();
function keys(o){return Object.keys(o||{}).sort().join('|');}
function sortedJson(x){
  if(Array.isArray(x))return '['+x.map(sortedJson).join(',')+']';
  if(x&&typeof x==='object')return '{'+Object.keys(x).sort().map(k=>JSON.stringify(k)+':'+sortedJson(x[k])).join(',')+'}';
  return JSON.stringify(x);
}
function bytes(s){return Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/')+'='.repeat((4-s.length%4)%4)),c=>c.charCodeAt(0));}
function hex(a){return Array.from(a).map(x=>x.toString(16).padStart(2,'0')).join('');}
async function sha(u){return hex(new Uint8Array(await crypto.subtle.digest('SHA-256',u)));}
function pemBytes(pem){
  const m=/^-----BEGIN PUBLIC KEY-----\r?\n([A-Za-z0-9+/=\r\n]+)-----END PUBLIC KEY-----\r?\n?$/.exec(pem);
  if(!m)throw Error('INVALID_SPKI_PEM');
  return bytes(m[1].replace(/\s/g,''));
}
function requestIso(s){const d=new Date(s);return /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/.test(s)&&Number.isFinite(d.getTime())&&d.toISOString().replace('.000Z','Z')===s;}
function reviewIso(s){const d=new Date(s);return /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(s)&&Number.isFinite(d.getTime())&&d.toISOString()===s;}
function fail(s){throw Error(s);}
/**
 * @param {{requestJson:string,receipt:object,publicRecord:object,job:object,trust:object,now?:number,expectedPublicFingerprint?:string}} args
 * Must only get trust from server-side enrolled-key registry (never from request body).
 */
export async function verifyOracleLabReview(args){
  const {requestJson,receipt,publicRecord,job,trust,now=Date.now(),expectedPublicFingerprint=TRUSTED_CORTANA_KEY_SHA}=args;
  if(typeof requestJson!=='string'||requestJson.length>2048||requestJson.length<100)fail('BAD_REQUEST_BYTES');
  let req;try{req=JSON.parse(requestJson)}catch{fail('BAD_REQUEST_JSON');}
  if(!req||Array.isArray(req)||keys(req)!==REQ_KEYS.join('|')||REQ_KEYS.some(k=>typeof req[k]!=='string'))fail('BAD_REQUEST_SHAPE');
  if(req.schema!==SCHEMA||req.device!=='Oracle'||req.operation!=='oracle_model_fixture_v1'||req.scope!=='disposable_lab_only'||req.artifact_sha256!==ARTIFACT)fail('BAD_ALLOWLIST');
  if(!UUID.test(req.request_id)||!H32.test(req.nonce))fail('BAD_REQUEST_ID');
  const begin=Date.parse(req.created_at),expires=Date.parse(req.expires_at);
  if(!requestIso(req.created_at)||!requestIso(req.expires_at)||begin>now+30000||begin<now-600000||expires<=now||expires>begin+600000)fail('EXPIRED_OR_INVALID_WINDOW');
  // This must be EXACTLY one fixed cloud action whose identifier/nonce matches this reviewer request.
  if(!job||job.id!==req.request_id||job.nonce!==req.nonce||job.schema!==JOB_SCHEMA||job.action!=='oracle_model_generate_v1'||job.operation!==OP||job.fixture!==FIXTURE||job.artifact_sha256!==ARTIFACT)fail('WRONG_CLOUD_JOB');
  if(!publicRecord||keys(publicRecord)!==PUB_KEYS.join('|')||publicRecord.role!=='lab_reviewer_only'||publicRecord.host!=='CORTANA'||publicRecord.reviewer_sid!=='S-1-5-19'||publicRecord.production_release_authorized!==false||publicRecord.cloud_enrolled!==false)fail('BAD_PUBLIC_RECORD');
  if(!trust||trust.role!=='lab_reviewer_only'||trust.enrollment_verified!==true||trust.revoked_at!==null||trust.public_key_sha256!==expectedPublicFingerprint)fail('TRUST_NOT_ENROLLED');
  if(publicRecord.public_key_sha256!==expectedPublicFingerprint)fail('KEY_NOT_PINNED');
  const spki=pemBytes(publicRecord.public_key_pem);
  if(await sha(spki)!==expectedPublicFingerprint)fail('SPKI_MISMATCH');
  if(!receipt||keys(receipt)!==ENVELOPE_KEYS.join('|')||typeof receipt.signature_b64url!=='string'||receipt.signature_b64url.length!==86)fail('BAD_RECEIPT_ENVELOPE');
  const payload=receipt.payload;
  if(!payload||keys(payload)!==RECEIPT_KEYS.join('|')||payload.schema!==RECEIPT_SCHEMA||payload.host!=='CORTANA'||payload.reviewer_sid!=='S-1-5-19'||payload.decision!=='LAB_ALLOW'||payload.reason!=='allowlisted_disposable_lab_only'||payload.execution_authorized!==false||payload.deployment_authorized!==false||payload.production_release_authorized!==false||payload.request_id!==req.request_id)fail('BAD_RECEIPT_SCOPE');
  if(!H64.test(payload.request_sha256)||payload.request_sha256!==await sha(encoder.encode(requestJson)))fail('REQUEST_HASH_MISMATCH');
  const reviewed=Date.parse(payload.reviewed_at);
  if(!reviewIso(payload.reviewed_at)||reviewed<begin||reviewed>expires||reviewed>now+30000)fail('INVALID_REVIEW_TIME');
  const key=await crypto.subtle.importKey('spki',spki,{name:'Ed25519'},false,['verify']);
  const valid=await crypto.subtle.verify('Ed25519',key,bytes(receipt.signature_b64url),encoder.encode(DOMAIN+sortedJson(payload)));
  if(!valid)fail('BAD_SIGNATURE');
  return Object.freeze({review_valid:true,lab_task_eligible:true,request_id:req.request_id,nonce:req.nonce,artifact_sha256:ARTIFACT,reviewer_key_sha256:expectedPublicFingerprint,expires_at:req.expires_at,production_deployment_authorized:false,source_change_authorized:false});
}
export {ARTIFACT,TRUSTED_CORTANA_KEY_SHA,sortedJson};
