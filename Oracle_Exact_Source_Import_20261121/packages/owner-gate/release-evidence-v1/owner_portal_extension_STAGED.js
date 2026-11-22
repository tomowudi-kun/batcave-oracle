/* Same original owner origin and existing confirmed-owner login. No key creation.
 * Copy only public evidence between the owner's authenticated device sessions.
 */
import('./release-evidence-v1/guided_first_key.mjs').then(({mountGuidedFirstKey})=>{
 mountGuidedFirstKey({
  origin:location.origin,
  api:async body=>{
   try{return await api(BASE+'/functions/v1/batcave-change-gate-v1',body);}
   catch(e){if(session?.refresh_token&&/invalid.*jwt|token.*expired|unauthorized|401/i.test(String(e.message))){await refresh();return api(BASE+'/functions/v1/batcave-change-gate-v1',body);}throw e;}
  },
  getOwnerId:()=>session?.user?.id,
  getOwnerEmail:()=>session?.user?.email,
  getOwnerKey:()=>{if(!session?.user?.id)throw Error('Sign in with your existing Batcave account.');return getKey(session.user.id);}
 });
}).catch(()=>{ /* No automatic authentication, signing, retries or key creation. */ });
