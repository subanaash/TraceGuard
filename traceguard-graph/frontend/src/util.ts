import type { Comparison, Findings, Run, Saved } from './types';

export function ago(iso?: string | null): string {
  if (!iso) return '';
  const s = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 60) return 'just now';
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`;
  return `${Math.floor(s / 86400)} d ago`;
}
export const when = (iso?: string | null) => (iso ? new Date(iso).toLocaleString() : '');

/** Old saved runs may miss newer fields, so fill safe defaults. */
export function normalize(f: Partial<Findings>, identity: string): Findings {
  return {
    identity, role: f.role ?? null, status: f.status ?? null, risk_level: f.risk_level ?? 'low',
    risk_reason: f.risk_reason ?? '', paths: f.paths ?? [], path_details: f.path_details ?? [],
    assets: f.assets ?? [], blast_radius: f.blast_radius ?? [], alerts: f.alerts ?? [],
    evidence: f.evidence ?? [], steps: f.steps ?? [], answer: f.answer, containment: f.containment ?? null,
  };
}

export function diff(cur: Findings, old?: Findings, oldTime?: string | null, count = 0): Comparison {
  if (!old) return { has_previous: false, previous_count: 0, new_assets: [], removed_assets: [], new_paths: [], removed_paths: [] };
  const sub = (a: string[], b: string[]) => a.filter(x => !b.includes(x)).sort();
  return {
    has_previous: true, baseline_time: oldTime, previous_count: count,
    new_assets: sub(cur.assets, old.assets), removed_assets: sub(old.assets, cur.assets),
    new_paths: sub(cur.paths, old.paths), removed_paths: sub(old.paths, cur.paths),
    previous_risk: old.risk_level, risk_changed: old.risk_level !== cur.risk_level,
  };
}

/** Turn a saved run into a Run, comparing it with the next-older run of the same identity. */
export function runFromSaved(s: Saved, all: Saved[]): Run {
  const same = all.filter(x => x.identity === s.identity).sort((a, b) => b.created_at.localeCompare(a.created_at));
  const idx = same.findIndex(x => x.id === s.id);
  const older = same[idx + 1];
  const f = normalize(s.findings, s.identity);
  return {
    id: s.id, identity: s.identity, created_at: s.created_at, findings: f,
    comparison: diff(f, older && normalize(older.findings, older.identity), older?.created_at, same.length - idx - 1),
  };
}

