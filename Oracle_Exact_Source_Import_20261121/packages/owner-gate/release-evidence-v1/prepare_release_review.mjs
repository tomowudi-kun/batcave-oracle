#!/usr/bin/env node
/* Public review inputs only. No signing, key reads, cloud writes or system install. */
import {createHash,randomUUID} from 'node:crypto';
import {readFileSync,writeFileSync,existsSync,mkdirSync,renameSync,rmSync} from 'node:fs';
import {join,dirname,resolve} from 'node:path';
import {homedir,platform,hostname} from 'node:os';
import {execFileSync} from 'node:child_process';
import {pathToFileURL} from 'node:url';
export const COMMIT='33b62fae6ccb2224f04cce43443510b71c051297';
const ARTIFACT_COMMIT='4b2bc0b698f46a263e7c84a07ea501b07cd20757';
const MINGIT={name:'MinGit-2.56.1-64-bit.zip',url:'https://github.com/git-for-windows/git/releases/download/v2.56.1.windows.1/MinGit-2.56.1-64-bit.zip',sha256:'4a92850b6e917da4fd010669b614b55dccf5b0ec333a534cc4be4700dfefdafd',bytes:39849768};
export const ARTIFACTS=[
 {name:'Oracle_Lab_OwnerGate_and_Portal_Review_v0.2.1.zip',sha256:'69ab19be8ec2e11e902716da59c2dda8693a3d3c78a16d8bdc1ded25a8d16851',bytes:34900},
 {name:'Oracle_Worker_Model_Integration_v0.3.1.zip',sha256:'4fd544067957242a8178631167e2d81ae1ba466e6ed1d7ee4109bf4d5cc6b6a2',bytes:34101}
].map(x=>({...x,url:'https://raw.githubusercontent.com/tomowudi-kun/batcave-oracle/'+ARTIFACT_COMMIT+'/release-artifacts/'+x.name}));
export const sha=b=>createHash('sha256').update(b).digest('hex');
export const quotePowerShell=s=>"'"+s.replace(/'/g,"''")+"'";
export function verifyBytes(bytes,expected){if(bytes.length!==expected.bytes||sha(bytes)!==expected.sha256)throw Error('REVIEW_INPUT_HASH_MISMATCH');}
async function download(input,path){
 if(existsSync(path)){verifyBytes(readFileSync(path),input);return;}
 const response=await fetch(input.url,{signal:AbortSignal.timeout(180000)});
 if(!response.ok||!response.body)throw Error('REVIEW_INPUT_DOWNLOAD_FAILED_'+response.status);
 const reader=response.body.getReader(),parts=[];let size=0;
 for(;;){const {value,done}=await reader.read();if(done)break;size+=value.length;if(size>input.bytes){await reader.cancel();throw Error('REVIEW_INPUT_TOO_LARGE');}parts.push(Buffer.from(value));}
 const bytes=Buffer.concat(parts);verifyBytes(bytes,input);
 const tmp=path+'.part-'+randomUUID();writeFileSync(tmp,bytes,{flag:'wx',mode:0o600});
 try{renameSync(tmp,path);}finally{if(existsSync(tmp))rmSync(tmp);}
}
function run(exe,args,extra={}){return execFileSync(exe,args,{encoding:'utf8',timeout:180000,stdio:['ignore','pipe','pipe'],...extra}).trim();}
function checkSource(git,repo){
 if(run(git,['-C',repo,'rev-parse','HEAD'])!==COMMIT||run(git,['-C',repo,'status','--porcelain']))throw Error('SOURCE_COMMIT_OR_DIRTY_WORKTREE');
}
export async function prepare(){
 if(platform()!=='win32'||process.arch!=='x64'||hostname().toUpperCase()!=='CORTANA')throw Error('USE_CORTANA_REVIEWER_WINDOW');
 const identity=run('whoami.exe',['/user','/fo','csv','/nh']),sid=identity.match(/"(S-1-5-21-[0-9-]+)"/)?.[1];
 if(!sid||!identity.toLowerCase().includes('strictnannyreviewer'))throw Error('USE_SEPARATE_REVIEWER_ACCOUNT');
 const root=join(homedir(),'Batcave-Oracle-Release-Review-v1');mkdirSync(root,{recursive:true,mode:0o700});
 run('icacls.exe',[root,'/inheritance:r','/grant:r','*'+sid+':(OI)(CI)F']);
 const ready=join(homedir(),'Batcave-Oracle-Release-Review-Ready.json');
 let git;
 for(const candidate of ['git','C:\\Program Files\\Git\\cmd\\git.exe','C:\\Program Files (x86)\\Git\\cmd\\git.exe']){
  try{run(candidate,['--version']);git=candidate;break;}catch{}
 }
 if(!git){
  console.log('Preparing verified portable Git in the reviewer folder.');
  const archive=join(root,MINGIT.name),target=join(root,'MinGit-2.56.1');
  await download(MINGIT,archive);
  if(!existsSync(target)){
   const stage=target+'.part-'+randomUUID();
   try{run('powershell.exe',['-NoProfile','-NonInteractive','-Command','Expand-Archive -LiteralPath '+quotePowerShell(archive)+' -DestinationPath '+quotePowerShell(stage)+' -ErrorAction Stop']);run(join(stage,'cmd','git.exe'),['--version']);renameSync(stage,target);}
   finally{if(existsSync(stage))rmSync(stage,{recursive:true});}
  }
  git=join(target,'cmd','git.exe');run(git,['--version']);
 }
 console.log('Preparing the two exact release archives.');
 for(const a of ARTIFACTS)await download(a,join(root,a.name));
 const repo=join(root,'reviewed-source'),hooks=join(root,'empty-hooks');mkdirSync(hooks,{recursive:true});
 if(!existsSync(repo)){
  console.log('Checking out the exact public release source.');
  const stage=repo+'.part-'+randomUUID();
  try{
   run(git,['-c','core.hooksPath='+hooks,'clone','--no-checkout','--depth','1','--branch','review/oracle-bootstrap-v021-worker-v031','https://github.com/tomowudi-kun/batcave-oracle.git',stage]);
   run(git,['-C',stage,'-c','core.hooksPath='+hooks,'fetch','--depth','1','origin',COMMIT]);
   run(git,['-C',stage,'-c','core.hooksPath='+hooks,'checkout','--detach',COMMIT]);
   checkSource(git,stage);renameSync(stage,repo);
  }finally{if(existsSync(stage))rmSync(stage,{recursive:true});}
 }
 checkSource(git,repo);
 const record={schema:'batcave.oracle.release.review.files.v1',source_commit:COMMIT,git_exe:git,repo_path:repo,gate_archive:join(root,ARTIFACTS[0].name),worker_archive:join(root,ARTIFACTS[1].name)};
 const tmp=ready+'.part-'+randomUUID();writeFileSync(tmp,JSON.stringify(record,null,2)+'\n',{flag:'wx',mode:0o600});renameSync(tmp,ready);
 console.log('RELEASE_REVIEW_FILES_READY');console.log('No signing or Oracle deployment occurred.');
 return record;
}
if(process.argv[1]&&import.meta.url===pathToFileURL(resolve(process.argv[1])).href)prepare().catch(e=>{console.error('PREPARATION STOPPED: '+e.message);process.exitCode=1;});
