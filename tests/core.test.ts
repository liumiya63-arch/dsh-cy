import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, appendFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { resolve, join } from 'node:path';
import { CyberCore } from '../src/host/core.js';

test('persist assets, findings, graph and knowledge; verify audit and detect tampering', async () => {
  const directory = mkdtempSync(join(tmpdir(), 'cyber-test-'));
  let core = new CyberCore(directory, resolve('recipes'));
  try {
    const a = await core.dispatch('asset.create', {type:'domain',value:'fixture.example'}) as {id:number};
    const b = await core.dispatch('asset.create', {type:'ip',value:'127.0.0.1'}) as {id:number};
    await core.dispatch('chain.create', {from:a.id,to:b.id,label:'resolves-to'});
    const finding = await core.dispatch('vulnerability.create', {title:'Fixture finding',severity:'low',assetId:a.id}) as {id:number};
    await core.dispatch('vulnerability.update', {id:finding.id,status:'fixed'});
    await core.dispatch('knowledge.ingest', {title:'Fixture',text:'Deterministic security retrieval evidence'});
    assert.equal((await core.dispatch('knowledge.search',{query:'retrieval'}) as unknown[]).length,1);
    assert.equal(core.verify().ok,true);
    await core.dispose();
    core = new CyberCore(directory,resolve('recipes'));
    assert.equal((core.snapshot().assets as unknown[]).length,2);
    assert.equal(core.verify().total,6);
    core.db.prepare("UPDATE audit SET detail='tampered' WHERE seq=2").run();
    assert.equal(core.verify().brokenAt,2);
  } finally { await core.dispose(); rmSync(directory,{recursive:true,force:true}); }
});

test('external tasks require user decisions; builtin health executes and is audited', async () => {
  const directory = mkdtempSync(join(tmpdir(), 'cyber-task-'));
  const core = new CyberCore(directory,resolve('recipes'));
  try {
    const pending = await core.dispatch('task.run',{recipe:'nmap-service',params:{target:'127.0.0.1'}}) as {status:string};
    assert.equal(pending.status,'awaiting_approval');
    const approval = (core.snapshot().approvals as {id:number}[])[0];
    await assert.rejects(core.dispatch('approval.decide',{id:approval.id,approved:true},'agent'),/user-only/);
    await core.dispatch('approval.decide',{id:approval.id,approved:false},'user');
    await assert.rejects(core.dispatch('task.run',{recipe:'nmap-service',params:{target:'--script=bad'}}),/Invalid target/);
    await core.dispatch('task.run',{recipe:'node-health',params:{}});
    await core.drain();
    const tasks = core.snapshot().tasks as {status:string,result:{stdout:string}}[];
    assert.equal(tasks[0].status,'completed');
    assert.match(tasks[0].result.stdout,/sqlite/);
    assert.equal(core.verify().ok,true);
    appendFileSync(core.jsonl,'{}\n');
    await assert.rejects(core.dispatch('audit.verify'),/differs/);
  } finally { await core.dispose(); rmSync(directory,{recursive:true,force:true}); }
});
