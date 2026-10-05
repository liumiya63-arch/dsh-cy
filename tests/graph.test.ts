import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { CyberCore } from '../src/host/core.js';
test('graph references, deterministic deduplication, persistence and scoped isolation', async()=>{
 const dir=mkdtempSync(join(tmpdir(),'cyber-graph-')); let core=new CyberCore(dir,'missing');
 try {
 const add=async(kind:string,input:Record<string,unknown>)=>await core.dispatch('graph.add_'+kind,input) as {uid:string;duplicate:boolean};
 const goal=await add('goal',{target:'localhost',objective:'verify'});
 assert.equal((await add('goal',{objective:'verify',target:'localhost'})).uid,goal.uid);
 const intent=await add('intent',{sourceId:goal.uid,title:'inspect health'});
 await assert.rejects(core.dispatch('graph.add_fact',{scope:'foreign',intentId:intent.uid,detail:'bad'}),/reference/);
 await assert.rejects(add('fact',{intentId:intent.uid,detail:'bad',confidence:2}),/confidence/);
 await assert.rejects(add('finding',{intentId:intent.uid,title:'x',severity:'low',description:'x',reproducibleSteps:[]}),/reproducibleSteps/);
 const asset=await add('asset',{type:'endpoint',value:'http://localhost/health'});
 await add('fact',{intentId:intent.uid,detail:'health responds',confidence:1});
 await add('finding',{intentId:intent.uid,title:'sample evidence',severity:'info',description:'test fixture',reproducibleSteps:['inspect health'],affectedAssetId:asset.uid});
 const graph=await core.dispatch('graph.state') as Record<string,unknown[]>;
 assert.equal(graph.edges.length,4); assert.equal(graph.findings.length,1); assert.equal(core.verify().ok,true);
 await core.dispose();core=new CyberCore(dir,'missing');
 assert.equal((await core.dispatch('graph.state') as Record<string,unknown[]>).goals.length,1);
 assert.equal((await core.dispatch('graph.state',{scope:'foreign'}) as Record<string,unknown[]>).goals.length,0);
 } finally {await core.dispose();rmSync(dir,{recursive:true,force:true});}
});
