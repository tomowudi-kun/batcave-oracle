/* STAGED source-only, non-authorizing regression: explicit Deno Node compatibility
 * and final-response authority-flag sealing. No network or production access.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {fileURLToPath} from 'node:url';
import path from 'node:path';
import {candidatePublicBytes} from '../src/general_control_reviewer_possession_STAGED.mjs';

const root=path.dirname(fileURLToPath(import.meta.url));
const source=(rel)=>readFileSync(path.join(root,rel),'utf8');

test('HARDEN-1: explicit node:buffer import and raw-key validation remain functional',()=>{
 const core=source('../src/general_control_reviewer_possession_STAGED.mjs');
 assert.match(core,/import \{Buffer\} from 'node:buffer';/);
 const sample=Buffer.alloc(32,0x2f);
 assert.deepEqual(candidatePublicBytes(sample.toString('base64url')),sample);
 assert.throws(()=>candidatePublicBytes('invalid'),/INVALID_PUBLIC_KEY/);
});

test('HARDEN-2: final envelope flags override downstream fields at BOTH boundaries',()=>{
 const handler=source('./handler_STAGED.mjs');
 const edge=source('./index.ts');
 const returns=handler.match(/return Object\.freeze\(\{\.\.\.result,registered:false,[\s\S]*?grant_issued:false\}\);/g)||[];
 assert.equal(returns.length,2,'issue and record responses must seal all six flags after result spread');
 assert.match(edge,/JSON\.stringify\(\{\.\.\.body,\.\.\.flags\}\)/);
 assert.match(edge,/from 'npm:@supabase\/server@1\.9\.2';/);
 assert.match(edge,/const flags=\{registered:false,independently_attested:false,[\s\S]*?production_release_authorized:false,execution_authorized:false,[\s\S]*?deployment_authorized:false,grant_issued:false\};/);
 assert.doesNotMatch(handler,/grant_issued:false,\.\.\.result/);
 assert.doesNotMatch(edge,/\{\.\.\.flags,\.\.\.body\}/);
});

