import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { parse } from 'yaml';
import { cyberTools } from '../src/host/tools.js';
test('native package root, loader and client module agree; Host is separate',()=>{
 const pkg=JSON.parse(readFileSync('package.json','utf8'));
 const patch=parse(readFileSync('cordis.patch.yml','utf8'));
 const rows=patch[0].insert;
 assert.equal(rows.find((r:{id:string})=>r.id==='dsh-cyber').name,pkg.name);
 assert.ok(readFileSync('client.js','utf8').includes(`id: '${pkg.name}'`));
 const preset=rows.find((r:{id:string})=>r.id==='preset-cyber-agent') as {config:{plugins:Array<{id:string;name:string}>}};
 assert.equal(preset.config.plugins.find(r=>r.id==='cyber-host')?.name,pkg.name+'/host');
 assert.equal(pkg.exports['./host'],'./lib/host/cyber.js');
 assert.ok(!readFileSync('src/host/index.ts','utf8').includes('CyberCore'));
 assert.equal(new Set(cyberTools.map(t=>t.name)).size,cyberTools.length);
 assert.ok(!cyberTools.some(t=>t.action==='approval.decide'));
});
