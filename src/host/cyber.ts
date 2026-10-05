import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { IncomingMessage, ServerResponse } from 'node:http';
import { CyberCore } from './core.js';
interface HostContext {
  effect(effect: () => (() => void | Promise<void>)): unknown;
  webServer: { register(route: { kind: 'prefix'; path: string; handler(req: IncomingMessage, res: ServerResponse): Promise<void> }): () => void };
  tools: { register(definition: unknown): () => void };
}
export const name = 'dsh-cyber';
export const inject = ['webServer', 'tools'];
const actions = ['snapshot','asset.create','asset.delete','vulnerability.create','vulnerability.update','chain.create','knowledge.ingest','knowledge.search','task.run','task.cancel','audit.verify'];
export function apply(ctx: HostContext, config: { dataPath?: string; recipesPath?: string } = {}): void {
  ctx.effect(() => {
    const core = new CyberCore(config.dataPath ?? join(process.env.DSH_PROFILE_DIR ?? process.cwd(), 'cyber-data'), config.recipesPath ?? join(dirname(fileURLToPath(import.meta.url)), '../../recipes'));
    const toolDispose = ctx.tools.register({ name: 'cyber_manage', description: 'Manage DSH Cyber assets, findings, knowledge and audited tool tasks. Call snapshot first to discover recipes and task state. Approval decisions are user-only.', parameters: { type: 'object', properties: { action: { type: 'string', enum: actions }, input: { type: 'object', additionalProperties: true } }, required: ['action'], additionalProperties: false }, output: { schema: { type: 'object', properties: { result: {} }, required: ['result'] }, render: (_args: unknown, value: unknown) => [{ type: 'text', text: JSON.stringify(value) }] }, execute: async (args: { action: string; input?: Record<string, unknown> }) => { if (!actions.includes(args.action)) throw new Error('Action not available to agents'); return { result: await core.dispatch(args.action, args.input ?? {}, 'agent') }; } });
    const routeDispose = ctx.webServer.register({ kind: 'prefix', path: '/api/cyber', handler: async (req, res) => {
      res.setHeader('Content-Type', 'application/json; charset=utf-8'); res.setHeader('Cache-Control', 'no-store');
      try {
        if (req.url?.split('?')[0] !== '/api/cyber') { res.statusCode = 404; res.end(JSON.stringify({ ok: false, error: 'Not found' })); return; }
        if (req.method !== 'POST' || req.headers['x-cyber-ui'] !== '1' || !req.headers['content-type']?.startsWith('application/json')) throw new Error('Expected JSON UI request');
        if (req.headers.origin && new URL(req.headers.origin).host !== req.headers.host) throw new Error('Origin mismatch');
        let bytes = 0; const chunks: Buffer[] = [];
        for await (const chunk of req) { const buffer = Buffer.from(chunk); bytes += buffer.length; if (bytes > 1200000) throw new Error('Request exceeds limit'); chunks.push(buffer); }
        const body = JSON.parse(Buffer.concat(chunks).toString()) as Record<string, unknown>;
        if (typeof body.action !== 'string' || ![...actions, 'approval.decide'].includes(body.action)) throw new Error('Action not available');
        const value = await core.dispatch(body.action, body, 'user'); res.end(JSON.stringify({ ok: true, value }));
      } catch (error) { res.statusCode = 400; res.end(JSON.stringify({ ok: false, error: error instanceof Error ? error.message : String(error) })); }
    } });
    return async () => { routeDispose(); toolDispose(); await core.dispose(); };
  });
}
