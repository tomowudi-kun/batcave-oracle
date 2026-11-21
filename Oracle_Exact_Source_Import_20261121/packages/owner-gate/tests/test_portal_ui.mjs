import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {webcrypto} from 'node:crypto';
import vm from 'node:vm';
const src=readFileSync(new URL('../portal/oracle-lab.js',import.meta.url),'utf8');
const id='123e4567-e89b-42d3-a456-426614174000';
function makeCtx(origin,fetch){
 const els=new Map();for(const name of ['enrollButton','scopeConsent','selfTest','status','output'])els.set(name,{disabled:false,checked:false,textContent:'',fn:null,addEventListener(_e,fn){this.fn=fn;}});
 const s=origin==='https://batcave-linux-approval.vercel.app'? JSON.stringify({access_token:'TEST-NONREAL',user:{id}}):null;
 const ctx={crypto:webcrypto,TextEncoder,Uint8Array,Date,Error,String,Object,Array,Number,Promise,RegExp,JSON,atob,btoa,
  location:{origin},sessionStorage:{getItem:()=>s},document:{getElementById:name=>els.get(name)},fetch,indexedDB:{open(){throw Error('key store should not be accessed in preview')}}, console};
 vm.createContext(ctx);vm.runInContext(src,ctx);return {ctx,els};
}
test('preview disables owner signing; offline test passes without network',async()=>{
 let calls=0;const {els}=makeCtx('https://batcave-linux-approval-preview.vercel.app',()=>{calls++;throw Error('network called')});
 assert.equal(els.get('enrollButton').disabled,true);
 await els.get('selfTest').fn();
 assert.match(els.get('status').textContent,/LAB_PASS/);
 const r=JSON.parse(els.get('output').textContent);assert.equal(r.owner_key_used,false);assert.equal(r.cloud_mutations,false);assert.equal(calls,0);
});
test('explicit owner click only, user must consent',async()=>{
 const {els}=makeCtx('https://batcave-linux-approval.vercel.app',()=>{throw Error('cloud should not run without consent')});
 assert.equal(els.get('enrollButton').disabled,false);
 await els.get('enrollButton').fn();assert.match(els.get('status').textContent,/Confirm the exact lab-only scope/);
});
test('source pins are exact and there is no owner key generation/export in enrollment route',()=>{
 assert.match(src,/S-1-5-19/);assert.match(src,/4fd544067957242a8178631167e2d81ae1ba466e6ed1d7ee4109bf4d5cc6b6a2/);
 assert.match(src,/4133fdbf40cb94461a1c2d0f2cd1f9f9e6484693e04f2ffa03bcd9cbc53a1b8b/);
 assert.match(src,/get\(uid\)/);assert.match(src,/crypto\.subtle\.sign\('Ed25519',key/);
 assert.doesNotMatch(src,/crypto\.subtle\.exportKey\s*\(/);
 assert.match(src,/open\.transaction\.abort\(\)/);
});
