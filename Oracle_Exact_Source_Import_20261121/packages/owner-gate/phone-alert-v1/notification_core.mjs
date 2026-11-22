/* Notification-only transport. Never signs, reviews, grants or executes a task. */
export const PORTAL_ORIGIN='https://batcave-linux-approval.vercel.app';
export const FLAGS=Object.freeze({deployment_authorized:false,execution_authorized:false,grant_issued:false});
export const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
export const HEX=/^[a-f0-9]{64}$/;
const encoder=new TextEncoder();
export const digest=async s=>Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',encoder.encode(s))),n=>n.toString(16).padStart(2,'0')).join('');
export function exact(x,keys){return x&&typeof x==='object'&&!Array.isArray(x)&&Object.keys(x).sort().join('|')===keys.split('|').sort().join('|');}
const must=(v,e)=>{if(!v)throw Error(e);};
function unbase64(s,n){
 must(typeof s==='string'&&/^[A-Za-z0-9_-]+$/.test(s),'INVALID_SUBSCRIPTION');
 const b=Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/')+'='.repeat((4-s.length%4)%4)),c=>c.charCodeAt(0));
 must(b.length===n&&btoa(String.fromCharCode(...b)).replace(/=/g,'').replace(/\+/g,'-').replace(/\//g,'_')===s,'INVALID_SUBSCRIPTION');return b;
}
export function validateSubscription(s){
 must(exact(s,'endpoint|expirationTime|keys')&&exact(s.keys,'p256dh|auth'),'INVALID_SUBSCRIPTION');
 must(typeof s.endpoint==='string'&&s.endpoint.length<4096,'INVALID_SUBSCRIPTION');
 let u;try{u=new URL(s.endpoint);}catch{throw Error('INVALID_SUBSCRIPTION');}
 // This first delivery targets the owner's Chrome phone. No arbitrary URL/SSRF.
 must(u.origin==='https://fcm.googleapis.com'&&!u.username&&!u.password&&!u.hash&&/^\/(fcm\/send|wp)\/[A-Za-z0-9_:\-]+$/.test(u.pathname)&&!u.search,'PUSH_ENDPOINT_NOT_ALLOWED');
 must(unbase64(s.keys.p256dh,65)[0]===4,'INVALID_SUBSCRIPTION');unbase64(s.keys.auth,16);
 must(s.expirationTime===null||Number.isFinite(s.expirationTime)&&s.expirationTime>Date.now(),'INVALID_SUBSCRIPTION');
 return {endpoint:u.href,expirationTime:s.expirationTime,keys:{p256dh:s.keys.p256dh,auth:s.keys.auth}};
}
export function notificationPayload(row,receiptToken,receiptUrl){
 must(row&&UUID.test(row.id)&&['review','test'].includes(row.kind)&&Date.parse(row.expires_at)>Date.now(),'NOTIFICATION_EXPIRED');
 return {schema:'batcave.phone.alert.v1',id:row.id,title:row.kind==='test'?'Batcave phone alerts':'Batcave needs your decision',body:row.kind==='test'?'Your phone received the test. Tap to open Batcave.':'Connect the existing Cortana reviewer? Tap to choose Yes or No.',url:PORTAL_ORIGIN+'/#owner-review',tag:'batcave-owner-review',expires_at:new Date(row.expires_at).toISOString(),receipt_token:receiptToken,receipt_url:receiptUrl,authorization_granted:false};
}
export async function handleOwnerNotification(body,owner,repo){
 try{
  must(owner?.authenticated===true&&UUID.test(owner.id),'UNAUTHORIZED');
  must(await repo.ownerExists(owner.id),'OWNER_KEY_REQUIRED');
  must(body&&typeof body==='object'&&!Array.isArray(body),'BAD_REQUEST');
  if(body.op==='status'){
   must(exact(body,'op')||exact(body,'op|subscription_id')&&UUID.test(body.subscription_id),'BAD_REQUEST');
   const config=await repo.ensureConfig(),r=body.subscription_id?await repo.getSubscription(owner.id,body.subscription_id):null;
   const last=r?await repo.latestDelivery(owner.id,r.id):null;
   return {status:200,body:{...FLAGS,public_key:config.public_key,subscription_id:r?.id||null,subscribed:!!r&&!r.disabled_at,delivery:last&&{id:last.id,send_state:last.send_state,shown_at:last.shown_at,opened_at:last.opened_at}}};
  }
  if(body.op==='subscribe'){
   must(exact(body,'op|subscription'),'BAD_REQUEST');const s=validateSubscription(body.subscription);
   await repo.ensureConfig();const r=await repo.subscribe(owner.id,s,await digest(s.endpoint));
   let deliveries=await repo.queue(owner.id,'review',r.id);
   if(!deliveries.length)deliveries=await repo.queue(owner.id,'test',r.id);
   return {status:200,body:{...FLAGS,subscription_id:r.id,notification_queued:deliveries.length>0,delivery_ids:deliveries}};
  }
  if(body.op==='test'||body.op==='disable'){
   must(exact(body,'op|subscription_id')&&UUID.test(body.subscription_id),'BAD_REQUEST');
   const r=await repo.getSubscription(owner.id,body.subscription_id);must(r&&!r.disabled_at,'SUBSCRIPTION_NOT_FOUND');
   if(body.op==='disable'){await repo.disable(owner.id,r.id);return {status:200,body:{...FLAGS,disabled:true}};}
   const ids=await repo.queue(owner.id,'test',r.id);must(ids.length>0,'ALERT_COOLDOWN');
   return {status:200,body:{...FLAGS,notification_queued:true,delivery_ids:ids}};
  }
  throw Error('UNSUPPORTED_ACTION');
 }catch(e){const msg=/^[A-Z][A-Z0-9_]{2,80}$/.test(e?.message||'')?e.message:'NOTIFICATION_UNAVAILABLE';return {status:msg==='UNAUTHORIZED'?401:msg==='NOTIFICATION_UNAVAILABLE'?503:403,body:{...FLAGS,error:msg}};}
}
export async function dispatchNotification(id,token,repo,generateRequest,fetcher,receiptUrl){
 must(UUID.test(id)&&HEX.test(token||''),'UNAUTHORIZED');
 const config=await repo.config();must(config&&await digest(token)===config.dispatch_hash,'UNAUTHORIZED');
 const receiptToken=Array.from(crypto.getRandomValues(new Uint8Array(32)),x=>x.toString(16).padStart(2,'0')).join('');
 const row=await repo.claim(id,await digest(receiptToken));
 if(!row)return {...FLAGS,dispatched:false};
 try{
  if(row.kind==='review'&&!await repo.reviewPending(row.owner_user_id)){await repo.finish(id,'cancelled');return {...FLAGS,dispatched:false};}
  const subscription=validateSubscription({endpoint:row.endpoint,expirationTime:null,keys:{p256dh:row.p256dh,auth:row.auth}});
  const secret=await repo.secret(config.secret_id),payload=notificationPayload(row,receiptToken,receiptUrl);
  const request=generateRequest(subscription,JSON.stringify(payload),{vapidDetails:{subject:'https://batcave-linux-approval.vercel.app',publicKey:config.public_key,privateKey:secret.privateKey},TTL:Math.max(1,Math.min(600,Math.floor((Date.parse(row.expires_at)-Date.now())/1000))),urgency:'normal',contentEncoding:'aes128gcm',topic:'batcave-owner-review'});
  must(request.endpoint===subscription.endpoint&&request.method==='POST','PUSH_REQUEST_INVALID');
  const response=await fetcher(request.endpoint,{method:'POST',headers:request.headers,body:request.body,redirect:'error',signal:AbortSignal.timeout(12000)});
  if(response.status===404||response.status===410){await repo.disable(row.owner_user_id,row.subscription_id);await repo.finish(id,'gone');}
  else if(response.status>=200&&response.status<300)await repo.finish(id,'sent');
  else await repo.finish(id,'failed');
  return {...FLAGS,dispatched:response.status>=200&&response.status<300};
 }catch{await repo.finish(id,'uncertain');return {...FLAGS,dispatched:false};}
}
export async function recordNotificationReceipt(body,repo){
 must(exact(body,'op|notification_id|token|stage')&&body.op==='receipt'&&UUID.test(body.notification_id)&&HEX.test(body.token||'')&&['shown','opened'].includes(body.stage),'BAD_REQUEST');
 const recorded=await repo.receipt(body.notification_id,await digest(body.token),body.stage);
 must(recorded,'RECEIPT_REJECTED');return {...FLAGS,recorded:true};
}
