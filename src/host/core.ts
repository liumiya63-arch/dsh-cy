import { DatabaseSync } from 'node:sqlite';
import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, readdirSync, writeFileSync, appendFileSync, existsSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { spawn, type ChildProcess } from 'node:child_process';
import { parse } from 'yaml';

type Input = Record<string, unknown>;
type Row = Record<string, unknown>;
interface Recipe { name: string; command: string; args: string[]; parameters?: Record<string, { required?: boolean; default?: string; pattern?: string }>; timeout?: number; risk_level: string; requires_approval?: boolean }
const hash = (value: unknown) => createHash('sha256').update(JSON.stringify(value)).digest('hex');
const text = (value: unknown, field: string, max = 10000): string => { if (typeof value !== 'string' || !value.trim() || value.length > max) throw new Error(`Invalid ${field}`); return value.trim(); };
const id = (value: unknown): number => { const n = Number(value); if (!Number.isSafeInteger(n) || n < 1) throw new Error('Invalid id'); return n; };
const choice = (value: unknown, values: string[], field: string): string => { if (!values.includes(String(value))) throw new Error(`Invalid ${field}`); return String(value); };
const json = (value: unknown) => JSON.stringify(value ?? null);
export class CyberCore {
  readonly db: DatabaseSync;
  readonly recipes: Recipe[] = [];
  private readonly running = new Map<number, ChildProcess>();
  private readonly jobs = new Set<Promise<unknown>>();
  private disposed = false;
  readonly jsonl: string;
  constructor(readonly dataPath: string, recipesPath: string) {
    mkdirSync(dataPath, { recursive: true });
    this.jsonl = join(dataPath, 'audit.jsonl');
    this.db = new DatabaseSync(join(dataPath, 'cyber.sqlite'));
    this.db.exec(`PRAGMA foreign_keys=ON; PRAGMA journal_mode=WAL;
      CREATE TABLE IF NOT EXISTS assets(id INTEGER PRIMARY KEY,type TEXT NOT NULL,value TEXT NOT NULL,metadata TEXT,created_at TEXT NOT NULL,UNIQUE(type,value));
      CREATE TABLE IF NOT EXISTS vulnerabilities(id INTEGER PRIMARY KEY,title TEXT NOT NULL,severity TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'open',assetId INTEGER REFERENCES assets(id) ON DELETE SET NULL,description TEXT,created_at TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS tasks(id INTEGER PRIMARY KEY,recipe TEXT NOT NULL,params TEXT NOT NULL,status TEXT NOT NULL,result TEXT,created_at TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS approvals(id INTEGER PRIMARY KEY,taskId INTEGER NOT NULL REFERENCES tasks(id),recipe TEXT NOT NULL,params TEXT NOT NULL,status TEXT NOT NULL,created_at TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS knowledge(id INTEGER PRIMARY KEY,title TEXT NOT NULL,text TEXT NOT NULL,created_at TEXT NOT NULL);
      CREATE VIRTUAL TABLE IF NOT EXISTS chunks USING fts5(documentId UNINDEXED,content);
      CREATE TABLE IF NOT EXISTS chains(id INTEGER PRIMARY KEY,"from" INTEGER REFERENCES assets(id) ON DELETE CASCADE,"to" INTEGER REFERENCES assets(id) ON DELETE CASCADE,label TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS audit(seq INTEGER PRIMARY KEY,timestamp TEXT NOT NULL,action TEXT NOT NULL,actor TEXT NOT NULL,detail TEXT NOT NULL,prev_hash TEXT,hash TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY,value TEXT NOT NULL);
      PRAGMA user_version=1;`);
    this.db.prepare("UPDATE tasks SET status='interrupted' WHERE status='running'").run();
    if (existsSync(recipesPath)) for (const file of readdirSync(recipesPath, { recursive: true })) {
      if (typeof file !== 'string' || !file.endsWith('.yaml')) continue;
      const recipe = parse(readFileSync(join(recipesPath, file), 'utf8')) as Recipe;
      text(recipe.name, 'recipe.name', 100); text(recipe.command, 'recipe.command', 500);
      if (!Array.isArray(recipe.args) || !recipe.args.every(a => typeof a === 'string') || this.recipes.some(r => r.name === recipe.name)) throw new Error(`Invalid recipe: ${file}`);
      choice(recipe.risk_level, ['low', 'medium', 'high', 'critical'], 'risk_level');
      if (recipe.timeout !== undefined && (!Number.isFinite(recipe.timeout) || recipe.timeout < 1 || recipe.timeout > 3600)) throw new Error('Invalid timeout');
      this.recipes.push(recipe);
    }
    if (!this.verify().ok) throw new Error('Audit chain damaged; recover before activation');
    this.recoverMirror();
  }
  private all(table: string): Row[] { return this.db.prepare(`SELECT * FROM ${table} ORDER BY id DESC LIMIT 500`).all() as Row[]; }
  private decode(row: Row): Row { const result = { ...row }; for (const field of ['params', 'result', 'metadata', 'detail']) if (typeof result[field] === 'string') { try { result[field] = JSON.parse(result[field] as string); } catch { /* Preserve malformed stored evidence. */ } } return result; }
  snapshot(): Row {
    return { assets: this.all('assets').map(r => this.decode(r)), vulnerabilities: this.all('vulnerabilities'), tasks: this.all('tasks').map(r => this.decode(r)), approvals: this.all('approvals').map(r => this.decode(r)), knowledge: this.all('knowledge').map(({ text: _, ...row }) => row), chains: this.all('chains'), audit: this.db.prepare('SELECT * FROM audit ORDER BY seq DESC LIMIT 200').all().map(r => this.decode(r as Row)), recipes: this.recipes, capabilities: { webshell: false, c2: false, retrieval: 'fts5', schemaVersion: 1 } };
  }
  private auditInTransaction(action: string, detail: unknown, actor: string): void {
    const prev = this.db.prepare('SELECT seq,hash FROM audit ORDER BY seq DESC LIMIT 1').get();
    const payload = { seq: Number(prev?.seq ?? 0) + 1, timestamp: new Date().toISOString(), action, actor, detail: json(detail), prev_hash: prev?.hash ?? null };
    this.db.prepare('INSERT INTO audit VALUES(?,?,?,?,?,?,?)').run(payload.seq, payload.timestamp, payload.action, actor, payload.detail, payload.prev_hash as string | null, hash(payload));
  }
  private mutate<T>(action: string, input: unknown, actor: string, fn: () => T): T {
    this.db.exec('BEGIN IMMEDIATE');
    let value: T;
    try { value = fn(); this.auditInTransaction(action, input, actor); this.db.exec('COMMIT'); } catch (error) { this.db.exec('ROLLBACK'); throw error; }
    this.recoverMirror();
    return value;
  }
  private recoverMirror(): void {
    const rows = this.db.prepare('SELECT * FROM audit ORDER BY seq').all();
    const lines = existsSync(this.jsonl) ? readFileSync(this.jsonl, 'utf8').split('\n').filter(Boolean) : [];
    if (lines.length > rows.length || lines.some((line, i) => line !== JSON.stringify(rows[i]))) throw new Error('Audit JSONL differs from committed database');
    if (lines.length < rows.length) appendFileSync(this.jsonl, rows.slice(lines.length).map(row => JSON.stringify(row) + '\n').join(''));
    else if (!existsSync(this.jsonl)) writeFileSync(this.jsonl, '');
  }
  verify(): { ok: boolean; total: number; brokenAt: number | null; anchored: false } {
    const rows = this.db.prepare('SELECT * FROM audit ORDER BY seq').all();
    let prev: string | null = null;
    for (let i = 0; i < rows.length; i++) {
      const { hash: digest, ...payload } = rows[i];
      if (payload.seq !== i + 1 || payload.prev_hash !== prev || hash(payload) !== digest) return { ok: false, total: rows.length, brokenAt: Number(payload.seq), anchored: false };
      prev = String(digest);
    }
    return { ok: true, total: rows.length, brokenAt: null, anchored: false };
  }
  async dispatch(action: string, input: Input = {}, actor = 'agent'): Promise<unknown> {
    if (this.disposed) throw new Error('Plugin disposed');
    if (action === 'snapshot') return this.snapshot();
    if (action === 'audit.verify') { const result = this.verify(); if (result.ok) this.recoverMirror(); return result; }
    if (action === 'asset.create') return this.mutate(action, input, actor, () => {
      const type = choice(input.type, ['domain', 'ip', 'port', 'service'], 'type');
      const value = text(input.value, 'value', 500);
      const result = this.db.prepare('INSERT INTO assets(type,value,metadata,created_at) VALUES(?,?,?,?)').run(type, value, json(input.metadata), new Date().toISOString());
      return { id: Number(result.lastInsertRowid), type, value };
    });
    if (action === 'asset.delete') return this.mutate(action, input, actor, () => ({ changes: this.db.prepare('DELETE FROM assets WHERE id=?').run(id(input.id)).changes }));
    if (action === 'vulnerability.create') return this.mutate(action, input, actor, () => ({ id: Number(this.db.prepare('INSERT INTO vulnerabilities(title,severity,assetId,description,created_at) VALUES(?,?,?,?,?)').run(text(input.title, 'title', 500), choice(input.severity, ['critical', 'high', 'medium', 'low', 'info'], 'severity'), input.assetId ? id(input.assetId) : null, String(input.description ?? '').slice(0, 50000), new Date().toISOString()).lastInsertRowid) }));
    if (action === 'vulnerability.update') return this.mutate(action, input, actor, () => ({ changes: this.db.prepare('UPDATE vulnerabilities SET status=? WHERE id=?').run(choice(input.status, ['open', 'confirmed', 'fixed', 'false_positive'], 'status'), id(input.id)).changes }));
    if (action === 'chain.create') return this.mutate(action, input, actor, () => ({ id: Number(this.db.prepare('INSERT INTO chains("from","to",label) VALUES(?,?,?)').run(id(input.from), id(input.to), text(input.label, 'label', 500)).lastInsertRowid) }));
    if (action === 'knowledge.ingest') return this.mutate(action, { title: input.title }, actor, () => {
      const title = text(input.title, 'title', 500), content = text(input.text, 'text', 1000000);
      const doc = Number(this.db.prepare('INSERT INTO knowledge(title,text,created_at) VALUES(?,?,?)').run(title, content, new Date().toISOString()).lastInsertRowid);
      for (let offset = 0; offset < content.length; offset += 800) this.db.prepare('INSERT INTO chunks(documentId,content) VALUES(?,?)').run(doc, content.slice(offset, offset + 1000));
      return { id: doc, retrieval: 'fts5' };
    });
    if (action === 'knowledge.search') {
      const tokens = text(input.query, 'query', 500).split(/\s+/).map(s => '"' + s.replaceAll('"', '""') + '"').join(' OR ');
      return this.db.prepare('SELECT documentId,content,bm25(chunks) AS score FROM chunks WHERE chunks MATCH ? ORDER BY score LIMIT 10').all(tokens);
    }
    if (action === 'task.run') return this.requestTask(input, actor);
    if (action === 'task.cancel') { const taskId = id(input.id); const child = this.running.get(taskId); if (!child) throw new Error('Task is not running'); this.stopChild(child); return { id: taskId, cancelling: true }; }
    if (action === 'approval.decide') {
      if (actor !== 'user') throw new Error('Approval is user-only');
      if (typeof input.approved !== 'boolean') throw new Error('Invalid approved');
      const approval = this.db.prepare("SELECT * FROM approvals WHERE id=? AND status='pending'").get(id(input.id));
      if (!approval) throw new Error('Pending approval not found');
      this.mutate(action, input, actor, () => {
        this.db.prepare('UPDATE approvals SET status=? WHERE id=?').run(input.approved ? 'approved' : 'rejected', Number(approval.id));
        this.db.prepare('UPDATE tasks SET status=? WHERE id=?').run(input.approved ? 'queued' : 'rejected', Number(approval.taskId));
      });
      if (input.approved) this.launch(Number(approval.taskId));
      return { id: approval.id, status: input.approved ? 'approved' : 'rejected' };
    }
    throw new Error(`Unknown action: ${action}`);
  }
  private prepare(recipe: Recipe, params: Input): string[] {
    const values: Record<string, string> = {};
    for (const [name, spec] of Object.entries(recipe.parameters ?? {})) {
      const value = params[name] ?? spec.default;
      if (value === undefined && spec.required) throw new Error(`Missing ${name}`);
      if (value !== undefined && (typeof value !== 'string' || value.length > 2000 || value.includes('\0') || (spec.pattern && !new RegExp(spec.pattern).test(value)))) throw new Error(`Invalid ${name}`);
      values[name] = String(value ?? '');
    }
    for (const name of Object.keys(params)) if (!(name in (recipe.parameters ?? {}))) throw new Error(`Unknown parameter ${name}`);
    return recipe.args.map(arg => arg.replace(/\{([a-zA-Z0-9_]+)\}/g, (_, name: string) => { if (!(name in values)) throw new Error(`Undefined parameter ${name}`); return values[name]; }));
  }
  private requestTask(input: Input, actor: string): Row {
    const recipe = this.recipes.find(r => r.name === input.recipe); if (!recipe) throw new Error('Recipe not registered');
    const params = input.params ?? {}; if (!params || typeof params !== 'object' || Array.isArray(params)) throw new Error('Invalid params');
    this.prepare(recipe, params as Input);
    // Require approval for every external tool, including low-risk recipes.
    const approvalRequired = recipe.command !== '@node-health' || recipe.requires_approval === true;
    const result = this.mutate('task.request', input, actor, () => {
      const taskId = Number(this.db.prepare('INSERT INTO tasks(recipe,params,status,created_at) VALUES(?,?,?,?)').run(recipe.name, json(params), approvalRequired ? 'awaiting_approval' : 'queued', new Date().toISOString()).lastInsertRowid);
      if (approvalRequired) this.db.prepare('INSERT INTO approvals(taskId,recipe,params,status,created_at) VALUES(?,?,?,\'pending\',?)').run(taskId, recipe.name, json(params), new Date().toISOString());
      return { id: taskId, status: approvalRequired ? 'awaiting_approval' : 'queued' };
    });
    if (!approvalRequired) this.launch(Number(result.id));
    return result;
  }
  private launch(taskId: number): void {
    const job = this.execute(taskId); this.jobs.add(job); job.finally(() => this.jobs.delete(job)).catch(() => {});
  }
  private stopChild(child: ChildProcess): void {
    if (process.platform === 'win32' && child.pid) spawn('taskkill', ['/pid', String(child.pid), '/T', '/F'], { stdio: 'ignore', windowsHide: true }).on('error', () => child.kill());
    else if (child.pid) { try { process.kill(-child.pid, 'SIGKILL'); } catch { child.kill('SIGKILL'); } }
  }
  private async execute(taskId: number): Promise<void> {
    const task = this.db.prepare('SELECT * FROM tasks WHERE id=?').get(taskId)!;
    const recipe = this.recipes.find(r => r.name === task.recipe)!;
    const params = JSON.parse(String(task.params)) as Input;
    const args = this.prepare(recipe, params);
    this.mutate('tool.start', { taskId, recipe: recipe.name }, 'system', () => this.db.prepare("UPDATE tasks SET status='running' WHERE id=?").run(taskId));
    const start = Date.now();
    let stdout = '', stderr = '', timedOut = false, overflow = false;
    const code = await new Promise<number | null>(resolveExit => {
      const builtin = recipe.command === '@node-health';
      const child = spawn(builtin ? process.execPath : recipe.command, builtin ? ['-e', 'console.log(JSON.stringify({node:process.version,sqlite:true}))'] : args, { shell: false, detached: process.platform !== 'win32', windowsHide: true, env: builtin ? { ...process.env, ELECTRON_RUN_AS_NODE: '1' } : { ...process.env } });
      this.running.set(taskId, child);
      const timer = setTimeout(() => { timedOut = true; this.stopChild(child); }, (recipe.timeout ?? 300) * 1000);
      const collect = (chunk: Buffer, stream: 'stdout' | 'stderr') => {
        if (Buffer.byteLength(stdout) + Buffer.byteLength(stderr) + chunk.length > 1048576) { overflow = true; this.stopChild(child); return; }
        if (stream === 'stdout') stdout += chunk.toString(); else stderr += chunk.toString();
      };
      child.stdout?.on('data', chunk => collect(chunk, 'stdout')); child.stderr?.on('data', chunk => collect(chunk, 'stderr'));
      child.on('error', error => { stderr += error.message; });
      child.on('close', exit => { clearTimeout(timer); this.running.delete(taskId); resolveExit(exit); });
    });
    const result = { stdout, stderr, exitCode: code, duration: Date.now() - start, timedOut, overflow };
    this.mutate('tool.finish', { taskId, ...result, stdout: undefined, stderr: undefined }, 'system', () => this.db.prepare('UPDATE tasks SET status=?,result=? WHERE id=?').run(timedOut ? 'timed_out' : overflow ? 'output_limit' : code === 0 ? 'completed' : 'failed', json(result), taskId));
  }
  async drain(): Promise<void> { await Promise.allSettled([...this.jobs]); }
  async dispose(): Promise<void> { this.disposed = true; for (const child of this.running.values()) this.stopChild(child); await this.drain(); this.db.close(); }
}
