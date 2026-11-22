import test from 'node:test';import assert from 'node:assert/strict';
import {verifyBytes,sha,quotePowerShell,ARTIFACTS,COMMIT} from './prepare_release_review.mjs';
test('review downloads fail closed on changed bytes, size and digest',()=>{
 const b=Buffer.from('public source fixture'),expected={bytes:b.length,sha256:sha(b)};
 assert.doesNotThrow(()=>verifyBytes(b,expected));
 assert.throws(()=>verifyBytes(Buffer.from('altered'),expected),/HASH_MISMATCH/);
 assert.throws(()=>verifyBytes(b,{...expected,sha256:'f'.repeat(64)}),/HASH_MISMATCH/);
});
test('PowerShell paths stay literal including apostrophes and expansion syntax',()=>{
 assert.equal(quotePowerShell("C:\\User's Folder\\$x;file.zip"),"'C:\\User''s Folder\\$x;file.zip'");
});
test('preparation keeps the approved release/source pins and public HTTPS destinations',()=>{
 assert.equal(COMMIT,'33b62fae6ccb2224f04cce43443510b71c051297');
 assert.deepEqual(ARTIFACTS.map(x=>x.sha256),['69ab19be8ec2e11e902716da59c2dda8693a3d3c78a16d8bdc1ded25a8d16851','4fd544067957242a8178631167e2d81ae1ba466e6ed1d7ee4109bf4d5cc6b6a2']);
 assert.ok(ARTIFACTS.every(x=>new URL(x.url).origin==='https://raw.githubusercontent.com'));
});
