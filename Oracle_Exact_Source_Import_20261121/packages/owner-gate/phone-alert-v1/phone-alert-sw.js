/* No fetch/cache handler; no login token, owner key or execution API access. */
const ORIGIN='https://batcave-linux-approval.vercel.app';
const RECEIPT='https://wizflveeptzeajsdybzs.supabase.co/functions/v1/batcave-phone-alert-v1';
const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
self.addEventListener('install',event=>event.waitUntil(self.skipWaiting()));
self.addEventListener('activate',event=>event.waitUntil(self.clients.claim()));
async function receipt(d,stage){try{await fetch(RECEIPT,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({op:'receipt',notification_id:d.id,token:d.receipt_token,stage}),cache:'no-store'});}catch{}}
function valid(d){return d?.schema==='batcave.phone.alert.v1'&&UUID.test(d.id)&&d.authorization_granted===false&&d.url===ORIGIN+'/#owner-review'&&d.receipt_url===RECEIPT&&/^[a-f0-9]{64}$/.test(d.receipt_token||'')&&typeof d.title==='string'&&d.title.length<=80&&typeof d.body==='string'&&d.body.length<=240&&Date.parse(d.expires_at)>Date.now()&&Date.parse(d.expires_at)<Date.now()+15*60*1000;}
self.addEventListener('push',event=>event.waitUntil((async()=>{
 let d;try{d=event.data.json();}catch{return;}
 if(!valid(d))return;
 await self.registration.showNotification(d.title,{body:d.body,icon:ORIGIN+'/doom-phone-icon.png',tag:'batcave-owner-review',data:d,renotify:true,actions:[{action:'review',title:'Review request'}]});
 await receipt(d,'shown');
})()));
self.addEventListener('notificationclick',event=>event.waitUntil((async()=>{
 event.notification.close();const d=event.notification.data;
 if(!valid(d))return;
 // A click opens the review page. It NEVER records Yes/No or signs anything.
 const opening=(async()=>{
  const windows=await self.clients.matchAll({type:'window',includeUncontrolled:true});
  const existing=windows.find(w=>new URL(w.url).origin===ORIGIN&&new URL(w.url).pathname==='/');
  if(existing){await existing.focus();existing.postMessage({type:'batcave-open-review'});}
  else await self.clients.openWindow(ORIGIN+'/#owner-review');
 })();
 await Promise.allSettled([opening,receipt(d,'opened')]);
})()));
self.addEventListener('message',event=>{
 if(event.data?.type!=='batcave-review-resolved')return;
 event.waitUntil((async()=>{for(const n of await self.registration.getNotifications({tag:'batcave-owner-review'}))n.close();})());
});
