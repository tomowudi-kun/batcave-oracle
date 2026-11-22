/* Existing owner origin, login and nonexportable signing key remain in place. */
const ownerApi=async(path,body)=>{
 try{return await api(BASE+'/functions/v1/'+path,body);}
 catch(e){if(session?.refresh_token&&/invalid.*jwt|token.*expired|unauthorized|401/i.test(String(e.message))){await refresh();return api(BASE+'/functions/v1/'+path,body);}throw e;}
};
import('./release-evidence-v1/guided_first_key.mjs').then(async({mountGuidedFirstKey})=>{
 const root=mountGuidedFirstKey({
  origin:location.origin,api:body=>ownerApi('batcave-change-gate-v1',body),proofApi:body=>ownerApi('batcave-first-proof-v1',body),
  getOwnerId:()=>session?.user?.id,getOwnerEmail:()=>session?.user?.email,
  getOwnerKey:()=>{if(!session?.user?.id)throw Error('Sign in with your existing Batcave account.');return getKey(session.user.id);}
 });
 try{const {mountPhoneAlerts}=await import('./phone-alert-v1/phone_alert_client.mjs');
  mountPhoneAlerts({root,api:body=>ownerApi('batcave-phone-alert-v1',body),getOwnerId:()=>session?.user?.id});
 }catch{ /* Existing Yes/No remains available if the notification module fails. */ }
}).catch(()=>{ /* No automatic authentication, signing or key creation. */ });
