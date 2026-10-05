import type { DatabaseSync } from 'node:sqlite';
import { createHash } from 'node:crypto';
type Input = Record<string, unknown>;
const required = (v: unknown, name: string): string => { if (typeof v !== 'string' || !v.trim() || v.length > 50000) throw new Error(`Invalid ${name}`); return v.trim(); };
const kinds = ['goal','intent','fact','finding','asset','edge'] as const;
export function initGraph(db: DatabaseSync): void {
  db.exec(`CREATE TABLE IF NOT EXISTS graph_records(uid TEXT PRIMARY KEY,kind TEXT NOT NULL,scope TEXT NOT NULL,data TEXT NOT NULL,created_at TEXT NOT NULL,UNIQUE(kind,scope,data)); CREATE INDEX IF NOT EXISTS graph_scope ON graph_records(scope,kind);`);
}
export function graphState(db: DatabaseSync, scope: string): Record<string, unknown[]> {
  const state: Record<string, unknown[]> = { goals: [], intents: [], facts: [], findings: [], assets: [], edges: [] };
  for (const row of db.prepare('SELECT * FROM graph_records WHERE scope=? ORDER BY created_at,uid LIMIT 3000').all(scope)) state[String(row.kind) === 'asset' ? 'assets' : `${row.kind}s`].push({ ...row, data: JSON.parse(String(row.data)) });
  return state;
}
export function addGraph(db: DatabaseSync, kind: string, input: Input, scope: string): unknown {
  if (!(kinds as readonly string[]).includes(kind)) throw new Error('Invalid graph kind');
  const ref = (uid: unknown, allowed: string[]): string => {
    const value = required(uid, 'reference');
    const row = db.prepare('SELECT kind FROM graph_records WHERE uid=? AND scope=?').get(value,scope);
    if (!row || !allowed.includes(String(row.kind))) throw new Error('Graph reference missing or wrong kind in this scope');
    return value;
  };
  const enumValue = (v: unknown, allowed: string[], name: string) => { const s=required(v,name); if(!allowed.includes(s))throw new Error(`Invalid ${name}`);return s; };
  let data: Input = {};
  if(kind==='goal') data={target:required(input.target,'target'),objective:required(input.objective,'objective'),authorization:String(input.authorization??'')};
  if(kind==='intent') data={sourceId:ref(input.sourceId,['goal','fact']),title:required(input.title,'title'),detail:String(input.detail??'')};
  if(kind==='fact') {
    const confidence=input.confidence??0.5;if(typeof confidence!=='number'||!Number.isFinite(confidence)||confidence<0||confidence>1)throw new Error('Invalid confidence');
    data={intentId:ref(input.intentId,['intent']),kind:enumValue(input.kind??'info',['port','service','http','info','vuln'],'fact kind'),target:String(input.target??''),detail:required(input.detail,'detail'),confidence};
  }
  if(kind==='finding') {
    if(!Array.isArray(input.reproducibleSteps)||!input.reproducibleSteps.length||!input.reproducibleSteps.every(s=>typeof s==='string'&&s.trim()))throw new Error('Finding requires reproducibleSteps');
    data={intentId:ref(input.intentId,['intent']),title:required(input.title,'title'),severity:enumValue(input.severity,['critical','high','medium','low','info'],'severity'),description:required(input.description,'description'),reproducibleSteps:input.reproducibleSteps};
    if(input.affectedAssetId)data.affectedAssetId=ref(input.affectedAssetId,['asset']);
  }
  if(kind==='asset') {
    data={type:enumValue(input.type,['domain','root-domain','subdomain','ip','port','service','app','endpoint'],'asset type'),value:required(input.value,'value'),meta:String(input.meta??'')};
    if(input.parentId)data.parentId=ref(input.parentId,['asset']);
  }
  if(kind==='edge') data={sourceId:ref(input.sourceId,[...kinds]),targetId:ref(input.targetId,[...kinds]),kind:enumValue(input.kind,['spawns','yields','derived_from','proves','parent','affects','related'],'edge kind')};
  // Fixed field construction preserves a canonical key order and deterministic IDs.
  const serialized=JSON.stringify(data);
  const uid=`${kind}-${createHash('sha256').update(JSON.stringify([scope,kind,data])).digest('hex').slice(0,24)}`;
  const existing=db.prepare('SELECT uid FROM graph_records WHERE uid=?').get(uid);
  db.prepare('INSERT OR IGNORE INTO graph_records VALUES(?,?,?,?,?)').run(uid,kind,scope,serialized,new Date().toISOString());
  if(kind==='intent') addGraph(db,'edge',{sourceId:data.sourceId,targetId:uid,kind:String(data.sourceId).startsWith('fact-')?'derived_from':'spawns'},scope);
  if(kind==='fact'||kind==='finding')addGraph(db,'edge',{sourceId:data.intentId,targetId:uid,kind:kind==='fact'?'yields':'proves'},scope);
  if(kind==='asset'&&data.parentId)addGraph(db,'edge',{sourceId:data.parentId,targetId:uid,kind:'parent'},scope);
  if(kind==='finding'&&data.affectedAssetId)addGraph(db,'edge',{sourceId:uid,targetId:data.affectedAssetId,kind:'affects'},scope);
  return {uid,kind,scope,data,duplicate:!!existing};
}
