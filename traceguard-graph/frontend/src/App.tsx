import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  Shield, Activity, Network, Search, Database, GitBranch, Clock3, AlertTriangle, RefreshCw,
  CheckCircle2, BrainCircuit, Plus, Trash2, Users, Bell, Cpu, Download,
} from 'lucide-react';
import GraphView from './GraphView';
import { API, api } from './api';
import { ago, diff, normalize, runFromSaved, when } from './util';
import type { ActionRecord, Containment, CutOption, Graph, GraphNode, IdentityInfo, Level, Run, Saved, TriageItem } from './types';
type Section = 'Overview' | 'Investigations' | 'Attack Surface' | 'Evidence & Signals' | 'Memory & Drift';
const NAV: { name: Section; icon: any }[] = [
  { name: 'Overview', icon: Activity }, { name: 'Investigations', icon: Search }, { name: 'Attack Surface', icon: Network },
  { name: 'Evidence & Signals', icon: Database }, { name: 'Memory & Drift', icon: BrainCircuit },
];

const Badge = ({ level }: { level: Level | string }) => <span className={'badge ' + level}>{String(level).toUpperCase()}</span>;

// Measured by the API: time for a trivial Cypher round-trip (RETURN 1) to FalkorDB. Shows "offline" if unreachable.
function FalkorTelemetryWidget() {
  const [ms, setMs] = useState<number | null>(null);
  const [offline, setOffline] = useState(false);

  useEffect(() => {
    let alive = true;
    const measure = async () => {
      try { const h = await api.health(); if (alive) { setMs(h.db_ms ?? null); setOffline(false); } }
      catch { if (alive) { setMs(null); setOffline(true); } }
    };
    void measure();
    const t = setInterval(measure, 5000);
    return () => { alive = false; clearInterval(t); };
  }, []);

  const color = offline ? '#f87171' : '#4ade80';
  return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', background: '#0c1422', border: '1px solid #1e293b', padding: '8px 10px', borderRadius: 8, marginBottom: '12px', fontSize: '11px', fontFamily: "'DM Mono', monospace", color: '#38bdf8' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
        <span style={{ width: '6px', height: '6px', borderRadius: '50%', background: color, boxShadow: `0 0 8px ${color}` }}></span>
        <span title="Cypher round-trip (RETURN 1) measured by the API">FalkorDB query</span>
      </div>
      <span style={{ color, fontWeight: 'bold' }}>{offline ? 'offline' : ms !== null ? `${ms}ms` : '…'}</span>
    </div>
  );
}

export default function App() {
  const [section, setSection] = useState<Section>('Overview');
  const [health, setHealth] = useState<'checking' | 'online' | 'offline'>('checking');
  const [graph, setGraph] = useState<Graph | null>(null);
  const [identities, setIdentities] = useState<IdentityInfo[]>([]);
  const [history, setHistory] = useState<Saved[]>([]);
  const [actions, setActions] = useState<ActionRecord[]>([]);
  const [identity, setIdentity] = useState('');
  const [customIdentityInput, setCustomIdentityInput] = useState('');
  const [useLlm, setUseLlm] = useState(false);
  const [run, setRun] = useState<Run | null>(null);
  const [loading, setLoading] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [selNode, setSelNode] = useState<GraphNode | null>(null);

  const refresh = useCallback(async () => {
    const [h, g, i, m, a] = await Promise.allSettled([api.health(), api.graph(), api.identities(), api.memory(), api.actions()]);    setHealth(h.status === 'fulfilled' ? 'online' : 'offline');
    if (g.status === 'fulfilled') setGraph(g.value);
    if (i.status === 'fulfilled') {
      setIdentities(i.value.identities);
      setIdentity(cur => cur || i.value.identities[0]?.name || '');
    }
    if (m.status === 'fulfilled') setHistory(m.value.investigations);
    if (a.status === 'fulfilled') setActions(a.value.actions);
  }, []);

  useEffect(() => {
    void refresh();
    const t = setInterval(() => void refresh(), 20000);
    return () => clearInterval(t);
  }, [refresh]);

  useEffect(() => {
    if (!notice) return;
    const t = setTimeout(() => setNotice(''), 7000);
    return () => clearTimeout(t);
  }, [notice]);

  async function guard<T>(fn: () => Promise<T>): Promise<T | undefined> {
    setError('');
    try { return await fn(); } catch (e) { setError((e as Error).message); }
  }

  async function seed() {
    setBusy(true);
    await guard(async () => { await api.seed(); await refresh(); setRun(null); setNotice('Demo graph reset. Saved investigations were kept.'); });
    setBusy(false);
  }

  async function investigate(name = identity) {
    const targetName = name.trim();
    if (!targetName) return;
    setIdentity(targetName); 
    setSection('Investigations'); 
    setLoading(true);
    await guard(async () => {
      const r = await api.investigate(targetName, useLlm);
      setRun({ id: r.investigation_id, identity: targetName, created_at: r.created_at, findings: normalize(r.findings, targetName), comparison: r.comparison, llm: r.llm, caution: r.caution });
      await refresh();
    });
    setLoading(false);
  }

   async function applyCut(edges: CutOption[], label: string) {
    const list = edges.map(e => `${e.from} ${e.relationship} ${e.to}`).join('\n');
    if (!window.confirm(`Apply this containment to the demo graph?\n\n${list}`)) return;
    setBusy(true);
    const ok = await guard(async () => {
        await api.contain(shown?.id, edges.map(e => ({ source: e.from, target: e.to, type: e.relationship })));
      return true;
    });
    setBusy(false);
    if (!ok) { await refresh(); return; }
    setNotice(`Applied: ${label}. Investigation re-run to show what changed.`);
    await investigate(identity);
  } 
    async function undoAction(id: string) {
    setBusy(true);
    const ok = await guard(async () => { await api.undoAction(id); await refresh(); return true; });
    setBusy(false);
    if (ok) setNotice('Action undone. The relationship was restored with its original source. Re-run the investigation to see the paths return.');
  }
    async function reviewFromTriage(name: string) {
    setIdentity(name); setRun(null); setSection('Investigations');
    await investigate(name);
  }

  async function clearAudit() {
    if (!window.confirm('Delete the whole audit trail? This cannot be undone.')) return;
    await guard(async () => { await api.clearActions(); await refresh(); setNotice('Audit trail cleared.'); });
  }

  async function addAndRun() {
    const name = customIdentityInput.trim();
    if (!name) return;
    if (!identities.some(i => i.name === name)) {
      const ok = await guard(async () => { await api.addIdentity(name); await refresh(); return true; });
      if (!ok) return;
    }
    setCustomIdentityInput('');
    await investigate(name);
  }

  function openSaved(s: Saved) { setRun(runFromSaved(s, history)); setIdentity(s.identity); setSection('Investigations'); }

  const runsFor = useCallback((name: string) => history.filter(h => h.identity === name), [history]);
  const latestFor = (name: string) => runsFor(name)[0];
  const shown: Run | null = run ?? (identity && latestFor(identity) ? runFromSaved(latestFor(identity), history) : null);
  const info = identities.find(i => i.name === identity);
  const openHigh = identities.reduce((n, i) => n + (i.high_alerts || 0), 0);
  const empty = health === 'online' && graph !== null && graph.node_count === 0;

  const hl = useMemo(() => {
    const nodes = new Set<string>(), edges = new Set<string>();
    shown?.findings.path_details.forEach(p => { p.nodes.forEach(n => nodes.add(n)); p.provenance.forEach(x => edges.add(`${x.from}|${x.to}`)); });
    return { nodes, edges };
  }, [shown]);

  // Exports the investigation currently on screen. Every number comes from that run; nothing is filled in.
  const handleExportReport = () => {
    if (!shown) return;
    const f = shown.findings;
    const report = {
      platform: 'TraceGuard',
      generated_at: new Date().toISOString(),
      synthetic_demo_data: true,
      investigation: { id: shown.id, identity: shown.identity, run_at: shown.created_at },
      graph: { nodes: graph?.node_count ?? null, relationships: graph?.edge_count ?? null },
      risk: { level: f.risk_level, reason: f.risk_reason },
      answer: f.answer ?? null,
      attack_paths: f.path_details,          // every hop carries the source system that asserted it
      blast_radius: f.blast_radius,
      alerts: f.alerts,
      evidence: f.evidence,
      change_since_previous_run: shown.comparison,
      measured_step_timings_ms: f.steps,
      caution: shown.caution ?? 'Synthetic demo data only. Graph reachability is not proof of compromise.',
    };
    const url = URL.createObjectURL(new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' }));
    const a = document.createElement('a');
    a.href = url;
    a.download = `traceguard-${shown.identity}-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="shell">
      <aside className="sidebar">
        <div className="brand"><div className="brandmark"><Shield size={23} /></div><div><b>TRACEGUARD</b><small>GRAPH SECURITY INTELLIGENCE</small></div></div>
        <div className="workspace-label">WORKSPACE</div>
        <nav>
          {NAV.map(x => (
            <button key={x.name} className={section === x.name ? 'nav active' : 'nav'} onClick={() => setSection(x.name)}>
              <x.icon size={17} />{x.name}
              {x.name === 'Memory & Drift' && history.length > 0 && <span className="nav-count">{history.length}</span>}
            </button>
          ))}
        </nav>
        
        <div className="side-bottom">
          <FalkorTelemetryWidget />
          <div className="system-status"><span className={health === 'online' ? 'dot' : 'dot red'} /><div><b>Graph database</b><small>{health === 'online' ? 'Connected' : health === 'checking' ? 'Checking…' : 'Not connected'}</small></div></div>
          <div className="side-footer">TRACEGUARD DEMO · V1.1<br />Synthetic security telemetry</div>
        </div>
      </aside>

      <main className="main">
        <header className="topbar">
          <div><span className="eyebrow">SECURITY OPERATIONS / GRAPH INTELLIGENCE</span><h1>{section}</h1></div>
          <div className="top-actions">
            <button 
              onClick={handleExportReport} disabled={!shown} title={shown ? 'Download this investigation as JSON' : 'Run an investigation first'}
              style={{ background: '#1e293b', color: '#38bdf8', border: '1px solid #38bdf844', padding: '6px 12px', borderRadius: '6px', cursor: 'pointer', fontSize: '11px', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '6px' }}
            >
              <Download size={14} /> Export Report
            </button>
            <span className="status-pill"><span className={health === 'online' ? 'dot' : 'dot red'} />{health === 'online' ? 'SYSTEM OPERATIONAL' : health === 'checking' ? 'CONNECTING' : 'API OFFLINE'}</span>
            <button className="icon-button" onClick={() => void refresh()} title="Refresh"><RefreshCw size={16} /></button>
          </div>
        </header>

        {health === 'offline' && <div className="error"><AlertTriangle size={17} /><span>Cannot reach the API at {API}. Run <code>docker compose up -d</code> and check <code>docker compose logs api</code>.</span><button onClick={() => void refresh()}>Retry</button></div>}
        {error && <div className="error"><AlertTriangle size={17} /><span>{error}</span><button onClick={() => setError('')}>Dismiss</button></div>}
        {notice && <div className="banner ok"><CheckCircle2 size={16} /><span>{notice}</span><button onClick={() => setNotice('')}>Dismiss</button></div>}
        {empty && <div className="banner"><Database size={16} /><span>The graph is empty. Load the synthetic demo data to get started.</span><button className="primary" disabled={busy} onClick={() => void seed()}>Seed demo data</button></div>}
        
        {section === 'Overview' && <>
          <section className="hero">
            <div>
              <div className="hero-kicker"><span className="pulse" /> GRAPH-NATIVE THREAT INVESTIGATION</div>
              <h2>Connect the evidence.<br /><em>Expose the attack path.</em></h2>
              <p>Investigate identities, map connected assets, and compare findings across time with persistent graph memory.</p>
              <div className="hero-actions">
                <button className="primary" onClick={() => setSection('Investigations')}><Search size={16} /> Start investigation</button>
                <button className="secondary" disabled={busy} onClick={() => void seed()}><Database size={16} /> Reset demo graph</button>
              </div>
            </div>
            <div className="hero-art"><div className="orbit orbit1" /><div className="orbit orbit2" /><div className="core"><Shield size={36} /></div>
              <div className="orb orb-a"><Users /></div><div className="orb orb-b"><Database /></div><div className="orb orb-c"><GitBranch /></div><div className="orb orb-d"><Activity /></div></div>
          </section>

          <section className="metric-grid">
            <Metric title="Graph entities" value={graph?.node_count ?? '—'} note="Identities, assets, alerts, evidence" icon={<Network />} />
            <Metric title="Relationships" value={graph?.edge_count ?? '—'} note="Connected graph edges" icon={<GitBranch />} />
            <Metric title="Saved investigations" value={history.length} note="Persistent memory records" icon={<BrainCircuit />} />
            <Metric title="High alerts" value={openHigh} note="High-severity alerts on identities" icon={<Bell />} />
          </section>

          <div className="section-title"><div><span className="eyebrow">IDENTITIES IN THE GRAPH</span><h3>Who to investigate</h3></div><span className="muted">{identities.length} identities</span></div>
          <div className="panel">
            {identities.length === 0 ? <div className="empty"><b>No identities yet</b><p>Seed the demo graph to load identities.</p></div> :
              <table className="table"><thead><tr><th>Identity</th><th>Role</th><th>Status</th><th>Alerts</th><th>Last investigation</th><th /></tr></thead><tbody>
                {identities.map(i => { const last = latestFor(i.name); return (
                  <tr key={i.name}>
                    <td><b>{i.name}</b></td><td>{i.role ?? '—'}</td>
                    <td><span className={'tag ' + (i.status === 'suspicious' ? 'warn' : '')}>{(i.status ?? 'unknown').toUpperCase()}</span></td>
                    <td>{i.alerts}{i.high_alerts > 0 && <span className="muted"> ({i.high_alerts} high)</span>}</td>
                    <td>{last ? <><Badge level={normalize(last.findings, last.identity).risk_level} /> <span className="muted">{ago(last.created_at)}</span></> : <span className="muted">Never</span>}</td>
                    <td><button className="secondary small" onClick={() => void investigate(i.name)}>Investigate</button></td>
                  </tr>); })}
              </tbody></table>}
          </div>

          <div className="section-title"><div><span className="eyebrow">RECENT ACTIVITY</span><h3>Latest investigations</h3></div></div>
          <div className="panel">
            {history.length === 0 ? <div className="empty"><b>Nothing run yet</b><p>Pick an identity above and run an investigation. Results are saved here.</p></div> :
              history.slice(0, 5).map(h => (
                <button key={h.id} className="memory-row clickable" onClick={() => openSaved(h)}>
                  <Clock3 size={15} /><div><b>{h.identity}</b><small>{when(h.created_at)} · {ago(h.created_at)}</small></div>
                  <Badge level={normalize(h.findings, h.identity).risk_level} /><code>{h.id.slice(0, 8)}</code>
                </button>))}
          </div>
        </>}
        {section === 'Investigations' && <div className="work-grid">
          <section className="panel investigate-panel">
            <div className="panel-head"><div><span className="eyebrow">AGENT WORKFLOW</span><h3>Run an investigation</h3></div><span className="tag">TOOL-ASSISTED</span></div>
            <p className="muted">Pick an identity from the graph, or add a new one and wire it to assets in Attack Surface.</p>
            
            <label className="field-label">SELECT IDENTITY / PRINCIPAL</label>
            <select className="select" value={identity} onChange={e => { setIdentity(e.target.value); setRun(null); }}>
              {identities.length === 0 && <option value="">No identities (seed the graph)</option>}
              {identities.map(i => <option key={i.name} value={i.name}>{i.name} — {i.role ?? 'unknown'}</option>)}
            </select>

            <label className="field-label" style={{ marginTop: '12px' }}>OR ADD A NEW IDENTITY (HAS NO ACCESS LINKS UNTIL YOU ADD THEM)</label>
            <div style={{ display: 'flex', gap: '8px' }}>
              <input 
                type="text" 
                className="select" 
                placeholder="e.g. custom.user or contractor.x" 
                value={customIdentityInput} 
                onChange={e => setCustomIdentityInput(e.target.value)}
                style={{ background: '#0c1422', color: '#f8fafc', border: '1px solid #334155', padding: '8px', borderRadius: '6px', flex: 1 }}
              />
              <button 
                className="secondary" 
                disabled={!customIdentityInput.trim()} 
                onClick={() => void addAndRun()}
              >
                Add & Run
              </button>
            </div>

            {info && <div className="idcard"><span className={'tag ' + (info.status === 'suspicious' ? 'warn' : '')}>{(info.status ?? 'unknown').toUpperCase()}</span><span className="muted">{info.alerts} alert(s) · {runsFor(info.name).length} saved run(s)</span></div>}
            
            <label className="toggle-row" style={{ marginTop: '16px' }}><input type="checkbox" checked={useLlm} onChange={e => setUseLlm(e.target.checked)} /><span><b>Use local Ollama summary</b><small>Optional. Graph analysis always runs; if Ollama is not available you will see a note.</small></span></label>
            
            <button className="primary full" disabled={loading || !identity} onClick={() => void investigate()}>
              {loading ? <><RefreshCw className="spin" size={16} /> Investigating…</> : <><Search size={16} /> Investigate identity</>}
            </button>
            
            <button className="secondary full" disabled={busy} onClick={() => void seed()}><Database size={16} /> Reset synthetic demo graph</button>
            
            {identity && runsFor(identity).length > 0 && <div className="pipeline"><span>RUN HISTORY · {identity}</span>
              {runsFor(identity).slice(0, 6).map(h => (
                <button key={h.id} className={'runlink' + (shown?.id === h.id ? ' active' : '')} onClick={() => openSaved(h)}>
                  <Badge level={normalize(h.findings, h.identity).risk_level} /> {ago(h.created_at)}
                </button>))}
            </div>}
          </section>

          <section className="panel result-panel">
            <div className="panel-head">
              <div><span className="eyebrow">{run ? 'LATEST RESULT' : shown ? 'LAST SAVED RESULT' : 'RESULT'}</span><h3>{shown ? `Investigation: ${shown.identity}` : 'Awaiting investigation'}</h3></div>
              {shown && <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}><Badge level={shown.findings.risk_level} /><span className="tag green"><CheckCircle2 size={12} /> {ago(shown.created_at).toUpperCase()}</span></div>}
            </div>
            
            {!shown ? (
              <div className="empty">
                <div className="empty-icon">
                  <Search size={25} />
                </div>
                <b>No investigation run yet</b>
                <p>
                  Run the agent to see findings, evidence, attack paths and risk exposure.
                </p>
              </div>
            ) : (
              <ResultView
                run={shown}
                busy={busy}
                onApply={applyCut}
              />
            )}
          </section>

        </div>}

        {section === 'Attack Surface' && <>
          <div className="section-title"><div><span className="eyebrow">LIVE GRAPH DATA</span><h3>Connected asset map</h3></div><button className="secondary" onClick={() => void refresh()}><RefreshCw size={14} /> Refresh graph</button></div>
          <div className="panel graph-panel">
            <div className="graph-legend">
              <span><i className="legend-dot identity" />Identity</span><span><i className="legend-dot asset" />Asset</span>
              <span><i className="legend-dot alert" />Alert</span><span><i className="legend-dot evidence" />Evidence</span>
              {hl.nodes.size > 0 && <span style={{ color: '#fb7185' }}>Red = attack paths of the {shown?.identity} investigation</span>}
              <span className="muted">{graph?.node_count ?? 0} nodes · {graph?.edge_count ?? 0} relationships</span>
            </div>
            {!graph || graph.nodes.length === 0 ? <div className="empty">Graph unavailable or empty. Start the Docker services and seed the demo.</div> :
              <div className="graph-layout">
                <GraphView graph={graph} highlightNodes={hl.nodes} highlightEdges={hl.edges} onSelect={setSelNode} />
                <aside className="side-panel">
                  {selNode ? <NodeDetails node={selNode} graph={graph} /> : <p className="muted">Click a node to see its properties and connections. Drag nodes to rearrange, scroll to zoom.</p>}
                </aside>
              </div>}
          </div>
          {graph && <ChangeForm graph={graph} guard={guard} onChanged={async msg => { await refresh(); setNotice(msg); }} />}
        </>}

        {section === 'Evidence & Signals' && <>
          <div className="section-title"><div><span className="eyebrow">PROVENANCE</span><h3>Evidence & alert signals{shown ? ` · ${shown.identity}` : ''}</h3></div>
            <select className="select inline" value={identity} onChange={e => { setIdentity(e.target.value); setRun(null); }}>{identities.map(i => <option key={i.name}>{i.name}</option>)}</select></div>
          <div className="panel">
            {!shown ? <div className="empty"><b>No investigation for {identity || 'this identity'} yet</b><p>Run an investigation to collect alerts and the evidence that supports them.</p><button className="primary" onClick={() => void investigate()}>Investigate {identity}</button></div> : <>
              <h4>Alerts ({shown.findings.alerts.length})</h4>
              {shown.findings.alerts.length === 0 && <p className="muted">No alerts involve this identity.</p>}
              {shown.findings.alerts.map(a => <div className="evidence-row" key={a.id}><AlertTriangle /><div><b>{a.id} · <Badge level={a.severity} /></b><p>{a.category}</p><small>{a.source}</small></div><span className="tag">SYNTHETIC</span></div>)}
              <h4>Evidence records ({shown.findings.evidence.length})</h4>
              {shown.findings.evidence.length === 0 && <p className="muted">No evidence is linked to this identity or the assets it can reach.</p>}
              {shown.findings.evidence.map(e => <div className="evidence-row" key={e.id}><Database /><div><b>{e.id}</b><p>{e.description}</p><small>{e.source}{e.supports ? ` · supports ${e.supports}` : ''}</small></div></div>)}
            </>}
          </div>
        </>}

        {section === 'Memory & Drift' && <MemoryView identities={identities} identity={identity} setIdentity={n => { setIdentity(n); setRun(null); }} history={history} openSaved={openSaved}
          onClear={async () => { if (!window.confirm(`Delete all saved investigations for ${identity}?`)) return; await guard(async () => { await api.clearMemory(identity); setRun(null); await refresh(); setNotice('History cleared.'); }); }}
          onGoInvestigate={() => setSection('Investigations')} />}
        {section === 'Memory & Drift' && <AuditTrail actions={actions} busy={busy} onUndo={undoAction} onClear={clearAudit} />}
        {section === 'Overview' && <TriagePanel guard={guard} onReview={name => void reviewFromTriage(name)} />}
        <footer>TRACEGUARD · GRAPH-NATIVE CYBER INVESTIGATION <span>DEMO DATA IS SYNTHETIC · NOT PRODUCTION SECURITY ADVICE</span></footer>
      </main>
    </div>
);
} 
function ResultView({ run, busy, onApply }: { run: Run; busy: boolean; onApply: (edges: CutOption[], label: string) => void }) {
  const f = run.findings;
  const high = f.blast_radius.filter(b => b.risk === 'high').length;
  const c = run.comparison;
  return <>
    <p className="answer">{f.answer ?? `${f.identity} is rated ${f.risk_level} risk.`}</p>
    {run.llm?.status === 'ok' && <div className="llm ok"><Cpu size={15} /><div><small>LOCAL LLM SUMMARY · {run.llm.model}</small><p>{run.llm.text}</p></div></div>}
    {run.llm?.status === 'unavailable' && <div className="llm"><Cpu size={15} /><div><small>LOCAL LLM NOT USED</small><p>{run.llm.error}</p></div></div>}
    {f.risk_reason && <p className="muted note">Why {f.risk_level}: {f.risk_reason}</p>}
    <div className="result-stats">
      <div><small>PATHS FOUND</small><b>{f.paths.length}</b></div>
      <div><small>REACHABLE ASSETS</small><b>{f.blast_radius.length}</b></div>
      <div><small>HIGH-SENSITIVITY</small><b>{high}</b></div>
    </div>

    {f.steps.length > 0 && <><h4>Agent steps (measured)</h4>
      <div className="steps">{f.steps.map((s, i) => <div className="step-row" key={s.name}><span className="step-n">{i + 1}</span><code>{s.name}</code><span className="muted">{s.count} result(s)</span><span className="ms">{s.duration_ms} ms</span></div>)}</div></>}

    <h4>Potential attack paths</h4>
    {f.path_details.length === 0 ? <p className="muted">No path from this identity to a high-sensitivity asset was found.</p> :
      f.path_details.map((p, i) => (
        <div className="path-card" key={i}>
          <div className="path-number">0{i + 1}</div>
          <div style={{ minWidth: 0 }}>
            <div className="chain">{p.nodes.map((n, j) => <span key={j} className="chain-part"><span className={'node-pill' + (j === p.nodes.length - 1 ? ' target' : '')}>{n}</span>{j < p.relationships.length && <span className="rel-label">{p.relationships[j].replace(/_/g, ' ').toLowerCase()} →</span>}</span>)}</div>
            <small>{p.provenance.map(x => `${x.from} → ${x.to}: ${x.source}`).join(' · ')}</small>
          </div>
        </div>))}
        <ContainPanel c={f.containment} busy={busy} onApply={onApply} />
    <h4>Blast radius</h4>
    {f.blast_radius.length === 0
      ? <p className="muted">No reachable assets from this identity.</p>
      : <div className="chips">{f.blast_radius.map(a => <span key={a.asset} className={'chip ' + a.risk}>{a.asset} · {a.sensitivity} · {a.hops === 0 ? 'direct' : `${a.hops} hop${a.hops > 1 ? 's' : ''}`}</span>)}</div>}
    <h4>Change since last run</h4>
    {!c.has_previous ? <p className="muted note">This is the first saved run for {f.identity}. Change the graph in Attack Surface and run again to see drift.</p> :
      <DriftSummary c={c} risk={f.risk_level} />}
    {run.caution && <div className="caution"><AlertTriangle size={16} /><span>{run.caution}</span></div>}
  </>;
}

const edgeText = (o: CutOption) => `${o.from} ${o.relationship.replace(/_/g, ' ').toLowerCase()} ${o.to}`;
const cutKey = (edges: CutOption[]) => edges.map(o => `${o.from}|${o.relationship}|${o.to}`).sort().join(',');

function CutSet({ title, hint, edges, busy, onApply }: { title: string; hint: string; edges: CutOption[]; busy: boolean; onApply: (edges: CutOption[], label: string) => void }) {
  if (edges.length === 0) return null;
  return <div className="path-card" style={{ display: 'block' }}>
    <b>{title}</b>
    <small>{hint}</small>
    {edges.map(o => <div className="kv" key={cutKey([o])}><span>{edgeText(o)}</span><b>removes {o.paths_removed}/{o.paths_total} · {o.source}</b></div>)}
    <button className="primary small" style={{ marginTop: 10 }} disabled={busy} onClick={() => onApply(edges, title)}>Apply cut & re-run</button>
  </div>;
}

function ContainPanel({ c, busy, onApply }: { c: Containment | null | undefined; busy: boolean; onApply: (edges: CutOption[], label: string) => void }) {
  if (!c) return null;
  const broad = c.recommended.some(o => o.kind === 'access');
  const same = cutKey(c.recommended) === cutKey(c.network_only);
  return <>
    <h4>Containment</h4>
    <p className="muted note">{c.note}</p>
    <CutSet title="Recommended: smallest cut that removes every path" busy={busy} onApply={onApply} edges={c.recommended}
      hint={broad ? 'Revokes access, which is the broadest action.' : 'Network changes only; the account keeps working.'} />
    {!same && <CutSet title="Alternative: keep access, cut the network routes" busy={busy} onApply={onApply} edges={c.network_only}
      hint="Needs more cuts, but the account keeps its access." />}
    <small className="muted">Single relationships ranked by paths removed:</small>
    <div className="chips" style={{ marginTop: 8 }}>{c.options.slice(0, 6).map(o => <span key={cutKey([o])} className="chip">{o.from} → {o.to} · removes {o.paths_removed}/{o.paths_total}</span>)}</div>
  </>;
}

const RISK_RANK: Record<string, number> = { low: 0, medium: 1, high: 2 };
function DriftSummary({ c, risk }: { c: Run['comparison']; risk?: string }) {
  const total = c.new_assets.length + c.removed_assets.length + c.new_paths.length + c.removed_paths.length + (c.risk_changed ? 1 : 0);
  if (!total) return <p className="muted note">No change compared with the previous run{c.baseline_time ? ` (${ago(c.baseline_time)})` : ''}.</p>;
  return <div className="drift">
    {c.risk_changed && c.previous_risk && risk && <div className={'drift-row ' + (RISK_RANK[risk] < RISK_RANK[c.previous_risk] ? 'del' : 'add')}>risk level: {c.previous_risk} → {risk}</div>}
    {c.new_paths.map(p => <div key={p} className="drift-row add">+ new path: {p}</div>)}
    {c.removed_paths.map(p => <div key={p} className="drift-row del">− path gone: {p}</div>)}
    {c.new_assets.map(p => <div key={p} className="drift-row add">+ newly reachable: {p}</div>)}
    {c.removed_assets.map(p => <div key={p} className="drift-row del">− no longer reachable: {p}</div>)}
  </div>;
}

function NodeDetails({ node, graph }: { node: GraphNode; graph: Graph }) {
  const name = (id: string) => graph.nodes.find(n => n.id === id)?.name ?? id;
  const out = graph.edges.filter(e => e.source === node.id), inc = graph.edges.filter(e => e.target === node.id);
  return <div>
    <span className="eyebrow">{node.type.toUpperCase()}</span><h4 style={{ margin: '6px 0 12px' }}>{node.name}</h4>
    {Object.entries(node.properties).filter(([k]) => k !== 'name').map(([k, v]) => <div className="kv" key={k}><span>{k}</span><b>{String(v)}</b></div>)}
    <h4>Outgoing ({out.length})</h4>{out.map(e => <div className="kv" key={e.id}><span>{e.type.toLowerCase()}</span><b>{name(e.target)}</b></div>)}
    <h4>Incoming ({inc.length})</h4>{inc.map(e => <div className="kv" key={e.id}><span>{e.type.toLowerCase()}</span><b>{name(e.source)}</b></div>)}
  </div>;
}

function ChangeForm({ graph, guard, onChanged }: { graph: Graph; guard: <T>(fn: () => Promise<T>) => Promise<T | undefined>; onChanged: (msg: string) => Promise<void> }) {
    const identityNames = graph.nodes.filter(n => n.type === 'Identity').map(n => n.name).sort();
  const assets = graph.nodes.filter(n => n.type === 'Asset').map(n => n.name).sort();
  const [src, setSrc] = useState(''), [dst, setDst] = useState(''), [rel, setRel] = useState('CONNECTS_TO');
  const sources = rel === 'HAS_ACCESS_TO' ? identityNames : assets;
  const s = sources.includes(src) ? src : sources[0] || '';
  const targets = assets.filter(a => a !== s);
  const d = targets.includes(dst) ? dst : targets[0] || '';
  const valid = Boolean(s && d && s !== d);
  return <div className="panel">
    <div className="panel-head"><div><span className="eyebrow">SIMULATE A CHANGE</span><h3>Edit a relationship</h3></div></div>
    <p className="muted">Add or remove a link, then re-run an investigation to see the drift in Memory & Drift.</p>
    <div className="form-row">
      <select className="select" value={s} onChange={e => setSrc(e.target.value)}>{sources.map(a => <option key={a}>{a}</option>)}</select>
      <select className="select" value={rel} onChange={e => setRel(e.target.value)}><option>CONNECTS_TO</option><option>DEPENDS_ON</option><option>HAS_ACCESS_TO</option></select>
      <select className="select" value={d} onChange={e => setDst(e.target.value)}>{targets.map(a => <option key={a}>{a}</option>)}</select>
      <button className="primary" disabled={!valid} onClick={() => void guard(async () => { await api.connect(s, d, rel); await onChanged(`Added: ${s} ${rel} ${d}. Re-run an investigation to see what changed.`); })}><Plus size={14} /> Add</button>
      <button className="secondary" disabled={!valid} onClick={() => void guard(async () => { await api.disconnect(s, d, rel); await onChanged(`Removed: ${s} ${rel} ${d}. Re-run an investigation to see what changed.`); })}><Trash2 size={14} /> Remove</button>
    </div>
  </div>;
}

function MemoryView({ identities, identity, setIdentity, history, openSaved, onClear, onGoInvestigate }: {
  identities: IdentityInfo[]; identity: string; setIdentity: (n: string) => void; history: Saved[];
  openSaved: (s: Saved) => void; onClear: () => void; onGoInvestigate: () => void;
}) {
  const runs = history.filter(h => h.identity === identity);
  const latest = runs[0] && runFromSaved(runs[0], history);
  return <>
    <div className="section-title"><div><span className="eyebrow">PERSISTENT INVESTIGATION MEMORY</span><h3>Cross-investigation comparison</h3></div>
      <div style={{ display: 'flex', gap: 8 }}>
        <select className="select inline" value={identity} onChange={e => setIdentity(e.target.value)}>{identities.map(i => <option key={i.name}>{i.name}</option>)}</select>
        {runs.length > 0 && <button className="secondary" onClick={onClear}><Trash2 size={14} /> Clear history</button>}
      </div></div>
    <div className="panel">
      {runs.length === 0 ? <div className="empty"><BrainCircuit size={28} /><b>No saved runs for {identity || 'this identity'}</b><p>TraceGuard saves every investigation so later runs can be compared.</p><button className="primary" onClick={onGoInvestigate}>Open investigation</button></div> : <>
        <div className="compare-intro"><div className="compare-icon"><BrainCircuit /></div><div><b>Latest run vs the one before, for {identity}</b><p>{runs.length} saved run(s). Latest: {when(runs[0].created_at)}</p></div></div>
        {latest && (latest.comparison.has_previous ? <>
          <div className="compare-grid">
            <Compare title="New assets" items={latest.comparison.new_assets} /><Compare title="New paths" items={latest.comparison.new_paths} />
            <Compare title="Removed assets" items={latest.comparison.removed_assets} /><Compare title="Removed paths" items={latest.comparison.removed_paths} /></div></> :
          <p className="muted note">Only one saved run so far. Run it again after changing the graph to see drift.</p>)}
        <h4>Timeline</h4>
        {runs.map((r, i) => {
          const f = normalize(r.findings, r.identity), older = runs[i + 1];
          const d = older ? diff(f, normalize(older.findings, older.identity)) : null;
          const delta = d ? (d.new_paths.length ? `+${d.new_paths.length} path(s)` : '') + (d.removed_paths.length ? ` −${d.removed_paths.length} path(s)` : '') || 'no change' : 'first run';
          return <button key={r.id} className="memory-row clickable" onClick={() => openSaved(r)}>
            <Clock3 size={15} /><div><b>{when(r.created_at)}</b><small>{f.paths.length} path(s) · {f.assets.length} asset(s) · {delta}</small></div><Badge level={f.risk_level} /><code>{r.id.slice(0, 8)}</code></button>;
        })}
      </>}
    </div>
  </>;
}
function AuditTrail({ actions, busy, onUndo, onClear }: { actions: ActionRecord[]; busy: boolean; onUndo: (id: string) => void; onClear: () => void }) {
  return <div className="panel">
    <div className="panel-head">
      <div><span className="eyebrow">AUDIT TRAIL</span><h3>Actions the agent applied</h3></div>
      <button className="secondary small" onClick={onClear} disabled={actions.length === 0}><Trash2 size={14} /> Clear audit trail</button>
    </div>
    {actions.length === 0
      ? <p className="muted">No containment actions yet. Apply a cut from an investigation and it will be recorded here.</p>
      : <table className="table">
          <thead><tr><th>When</th><th>Action</th><th>Edge source</th><th>Proposed by run</th><th>Status</th><th></th></tr></thead>
          <tbody>{actions.map(a => <tr key={a.id}>
            <td>{new Date(a.created_at).toLocaleString()}</td>
            <td><b>Cut</b> {a.from} {a.relationship.replace(/_/g, ' ').toLowerCase()} {a.to}</td>
            <td>{a.edge_source ?? 'unknown'}</td>
            <td><code>{a.investigation_id ? a.investigation_id.slice(0, 8) : '—'}</code></td>
            <td><span className={'badge ' + (a.status === 'applied' ? 'medium' : 'low')}>{a.status}</span></td>
            <td>{a.status === 'applied' && <button className="secondary small" disabled={busy} onClick={() => onUndo(a.id)}>Undo</button>}</td>
          </tr>)}</tbody>
        </table>}
  </div>;
}
function TriagePanel({ guard, onReview }: { guard: <T>(fn: () => Promise<T>) => Promise<T | undefined>; onReview: (name: string) => void }) {
  const [items, setItems] = useState<TriageItem[] | null>(null);
  const [busy, setBusy] = useState(false);
  const scan = async () => { setBusy(true); await guard(async () => { setItems((await api.triage()).items); }); setBusy(false); };
  return <div className="panel">
    <div className="panel-head">
      <div><span className="eyebrow">AGENT TRIAGE</span><h3>Triage queue</h3></div>
      <button className="primary small" disabled={busy} onClick={() => void scan()}><Search size={14} /> {busy ? 'Scanning…' : 'Scan all identities'}</button>
    </div>
    <p className="muted">Read-only scan of every identity, ranked by risk. Nothing is saved or changed until you review one and apply its cut.</p>
    {items && <table className="table">
      <thead><tr><th>Identity</th><th>Risk</th><th>Paths</th><th>Alerts</th><th>Proposed containment</th><th></th></tr></thead>
      <tbody>{items.map(t => <tr key={t.identity}>
        <td><b>{t.identity}</b><br /><span className="muted">{t.role}</span></td>
        <td><span className={'badge ' + t.risk_level}>{t.risk_level}</span></td>
        <td>{t.paths}</td><td>{t.alerts}</td>
        <td>{t.proposal.length
          ? t.proposal.map(o => `${o.from} ${o.relationship.replace(/_/g, ' ').toLowerCase()} ${o.to} (removes ${o.paths_removed}/${o.paths_total})`).join('; ')
          : 'No containment needed'}</td>
        <td><button className="secondary small" onClick={() => onReview(t.identity)}>Review & contain</button></td>
      </tr>)}</tbody>
    </table>}
  </div>;
}
function Metric({ title, value, note, icon }: { title: string; value: any; note: string; icon: any }) {
  return <div className="metric"><div className="metric-top"><span>{title}</span><div>{icon}</div></div><strong>{value}</strong><small>{note}</small></div>;
}

function Compare({ title, items }: { title: string; items: string[] }) {
  return (
    <div className="compare-box">
      <small>{title.toUpperCase()}</small>
      <b>{items.length}</b>
      {items.length > 0 ? (
        <p>{items.join(', ')}</p>
      ) : (
        <p>No changes detected</p>
      )}
    </div>
  );
}
