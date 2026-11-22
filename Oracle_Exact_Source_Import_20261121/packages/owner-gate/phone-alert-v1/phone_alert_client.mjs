/* Opt-in browser notifications on the existing owner-key origin. */
const STORAGE='batcave_phone_push_subscription_v1';
function decode(s){return Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/')+'='.repeat((4-s.length%4)%4)),c=>c.charCodeAt(0));}
function friendly(e){const s=String(e?.message||e);if(/UNAUTHORIZED|Sign in|401|JWT/i.test(s))return 'Sign in above with your existing Batcave account.';if(/ALERT_COOLDOWN/.test(s))return 'An alert was just queued. Wait a moment before testing again.';if(/PUSH_ENDPOINT_NOT_ALLOWED/.test(s))return 'Use Chrome on your phone for this notification connection.';if(/permission|denied|blocked/i.test(s))return 'Chrome has blocked notifications for this page. Allow notifications in its site settings, then try again.';return 'Phone alerts could not connect. '+s;}
export function mountPhoneAlerts({root,api,getOwnerId}){
 const panel=document.createElement('div');panel.className='phone-alert-controls';
 panel.innerHTML='<h2>Phone alerts</h2><p>Dr. Doom can alert you when Batcave needs a decision. Tap the alert to open Yes or No.</p><button data-enable-alerts>Enable phone alerts</button><button data-test-alert hidden>Send test alert</button><button data-disable-alerts hidden>Turn alerts off</button><p data-alert-status role="status" aria-live="polite"></p>';
 root.append(panel);
 const q=s=>panel.querySelector(s),show=s=>{q('[data-alert-status]').textContent=s;};
 let id;try{id=localStorage.getItem(STORAGE)||null;}catch{}let busy=false,pollCount=0,poll;
 const supported='serviceWorker'in navigator&&'PushManager'in window&&'Notification'in window&&isSecureContext;
 function paint(subscribed){q('[data-enable-alerts]').hidden=!!subscribed;q('[data-test-alert]').hidden=!subscribed;q('[data-disable-alerts]').hidden=!subscribed;for(const b of panel.querySelectorAll('button'))b.disabled=busy;}
 async function update(){
  if(!id||!getOwnerId())return;
  const s=await api({op:'status',subscription_id:id});if(!s.subscribed){id=null;localStorage.removeItem(STORAGE);}paint(s.subscribed);
  if(s.delivery?.shown_at){show('Your phone confirmed that the alert was displayed. Tap it to open the approval page.');clearInterval(poll);}
  else if(['failed','gone','uncertain','cancelled'].includes(s.delivery?.send_state)){show('Delivery was not confirmed. Use Send test alert to check again.');clearInterval(poll);}
  else if(s.delivery?.send_state==='sent')show('The push service accepted the alert. Waiting for this phone to confirm it.');
  if(++pollCount>=12)clearInterval(poll);
 }
 function watch(){clearInterval(poll);pollCount=0;poll=setInterval(()=>update().catch(e=>{show(friendly(e));clearInterval(poll);}),2500);}
 async function act(fn){if(busy)return;busy=true;paint(!!id);try{if(!getOwnerId())throw Error('Sign in first');await fn();}catch(e){show(friendly(e));}finally{busy=false;paint(!!id);}}
 q('[data-enable-alerts]').onclick=()=>{
  if(!supported){show('Phone alerts need Chrome and notification support.');return;}
  if(!getOwnerId()){show('Sign in above with your existing Batcave account.');return;}
  // Permission request starts in the owner's actual tap, never automatically.
  const permission=Notification.requestPermission();
  return act(async()=>{
   if(await permission!=='granted')throw Error('Notification permission denied');
   const registration=await navigator.serviceWorker.register('/phone-alert-sw.js',{scope:'/'});
   await navigator.serviceWorker.ready;
   const config=await api({op:'status'});let sub=await registration.pushManager.getSubscription();
   if(!sub)sub=await registration.pushManager.subscribe({userVisibleOnly:true,applicationServerKey:decode(config.public_key)});
   const result=await api({op:'subscribe',subscription:sub.toJSON()});id=result.subscription_id;localStorage.setItem(STORAGE,id);
   show(result.notification_queued?'Alert queued. Waiting for this phone to confirm delivery.':'Alerts are connected. Use Send test alert to check delivery.');watch();
  });
 };
 q('[data-test-alert]').onclick=()=>act(async()=>{await api({op:'test',subscription_id:id});show('Test alert queued. Waiting for this phone to confirm delivery.');watch();});
 q('[data-disable-alerts]').onclick=()=>act(async()=>{await api({op:'disable',subscription_id:id});const r=await navigator.serviceWorker.getRegistration('/');const s=await r?.pushManager.getSubscription();if(s)await s.unsubscribe();id=null;localStorage.removeItem(STORAGE);clearInterval(poll);show('Phone alerts are off.');});
 root.addEventListener('batcave-owner-decision',()=>{navigator.serviceWorker?.controller?.postMessage({type:'batcave-review-resolved'});});
 navigator.serviceWorker?.addEventListener('message',event=>{if(event.data?.type==='batcave-open-review')root.scrollIntoView({behavior:'smooth',block:'start'});});
 if(!supported){q('[data-enable-alerts]').disabled=true;show('Use Chrome on your phone to enable alerts.');}else{paint(!!id);if(id)update().catch(e=>show(friendly(e)));}
 return panel;
}
