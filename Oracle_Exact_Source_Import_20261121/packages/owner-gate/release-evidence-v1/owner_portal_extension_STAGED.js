/* Append to the existing original-origin owner portal app.js AFTER independent
 * review. Existing BASE, api, getKey and session bindings are reused unchanged.
 * Copy the release modules into /release-evidence-v1/ on that SAME origin.
 * This file is a reviewed integration instruction, not deployed production code.
 */
import('./release-evidence-v1/release_owner_panel.mjs').then(({mountReleasePanel})=>{
 mountReleasePanel({
  origin:location.origin,
  api:body=>api(BASE+'/functions/v1/batcave-change-gate-v1',body),
  getOwnerId:()=>session?.user?.id,
  getOwnerKey:()=>{if(!session?.user?.id)throw Error('Sign in with the existing owner account.');return getKey(session.user.id);}
 });
}).catch(()=>{ /* No automatic retries, authentication, signing or key creation. */ });
