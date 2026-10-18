import type { Graph, TriageItem,IdentityInfo, Saved, Comparison, Findings, Llm, Step, Simulation, ActionRecord } from './types';
export const API: string =
  (import.meta.env.VITE_API_URL as string | undefined) ?? `${window.location.protocol}//${window.location.hostname}:8000`;

async function call<T>(path: string, init?: RequestInit): Promise<T> {
  let r: Response;
  try {
    r = await fetch(API + path, init);
  } catch {
    throw new Error(`Cannot reach the API at ${API}. Check that "docker compose up" is running.`);
  }
  const text = await r.text();
  let data: any = null;
  try { data = text ? JSON.parse(text) : null; } catch { /* not json */ }
  if (!r.ok) {
    const d = data?.detail;
    throw new Error(typeof d === 'string' ? d : Array.isArray(d) ? d.map((x: any) => x.msg).join(', ') : `Request failed (${r.status})`);
  }
  return data as T;
}
const post = (path: string, body?: unknown) =>
  call<any>(path, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: body ? JSON.stringify(body) : undefined });

export type InvestigateResponse = {
  investigation_id: string; created_at: string; findings: Findings; comparison: Comparison;
  llm: Llm; steps: Step[]; caution: string;
};

export const api = {
  health: () => call<{ status: string; db_ms?: number }>('/health'),
  graph: () => call<Graph>('/graph/data'),
  identities: () => call<{ identities: IdentityInfo[] }>('/identities'),
  memory: () => call<{ investigations: Saved[] }>('/memory'),
  seed: () => post('/demo/seed'),
  investigate: (identity: string, use_llm: boolean) => post('/agent/investigate', { identity, use_llm }) as Promise<InvestigateResponse>,
  connect: (source: string, target: string, type: string) => post('/graph/connect', { source, target, type }),
  disconnect: (source: string, target: string, type: string) => post('/graph/disconnect', { source, target, type }),
  simulate: (node: string, depth = 3) => post('/graph/simulate', { node, depth }) as Promise<{ status: string; data: Simulation }>,
  addIdentity: (name: string) => post('/graph/identity', { name }),
  clearMemory: (identity: string) => call<any>('/memory?identity=' + encodeURIComponent(identity), { method: 'DELETE' }),
  contain: (investigation_id: string | undefined, edges: { source: string; target: string; type: string }[]) => post('/graph/contain', { investigation_id, edges }),
  actions: () => call<{ actions: ActionRecord[] }>('/actions'),
  undoAction: (id: string) => post(`/actions/${id}/undo`),
  clearActions: () => call<any>('/actions', { method: 'DELETE' }),
  triage: () => post('/agent/triage') as Promise<{ items: TriageItem[] }>,
};