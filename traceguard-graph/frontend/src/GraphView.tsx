import { useState, useMemo } from 'react';
import { ReactFlow, Background, Controls, MarkerType, type Node, type Edge } from '@xyflow/react';
import { api } from './api';
import type { Graph, GraphNode } from './types';

const COLORS: Record<string, string> = { Identity: '#f59e0b', Asset: '#38bdf8', Alert: '#fb7185', Evidence: '#34d399' };
const SOFT = new Set(['INVOLVES', 'SUPPORTED_BY']);
const FLOW = new Set(['HAS_ACCESS_TO', 'CONNECTS_TO', 'DEPENDS_ON']);

/** Lay the graph out in columns by distance from the identities. Alerts go on top, evidence at the bottom. */
function layout(graph: Graph) {
  const byId = new Map(graph.nodes.map(n => [n.id, n]));
  const depth = new Map<string, number>();
  const queue = graph.nodes.filter(n => n.type === 'Identity').map(n => n.id);
  queue.forEach(id => depth.set(id, 0));
  while (queue.length) {
    const id = queue.shift()!;
    for (const e of graph.edges) {
      if (e.source === id && FLOW.has(e.type) && !depth.has(e.target)) { depth.set(e.target, depth.get(id)! + 1); queue.push(e.target); }
    }
  }
  const pos = new Map<string, { x: number; y: number }>();
  const cols = new Map<number, GraphNode[]>();
  graph.nodes.filter(n => n.type === 'Identity' || n.type === 'Asset').forEach(n => {
    const d = depth.get(n.id) ?? 1;
    cols.set(d, [...(cols.get(d) ?? []), n]);
  });
  let maxRows = 1;
  cols.forEach((list, d) => {
    list.sort((a, b) => (a.name ?? '').localeCompare(b.name ?? ''));
    maxRows = Math.max(maxRows, list.length);
    list.forEach((n, i) => pos.set(n.id, { x: d * 270, y: 150 + i * 100 }));
  });
  graph.nodes.filter(n => n.type === 'Alert').forEach((n, i) => pos.set(n.id, { x: i * 240, y: 0 }));
  graph.nodes.filter(n => n.type === 'Evidence').forEach((n, i) => pos.set(n.id, { x: i * 240, y: 150 + maxRows * 100 + 60 }));
  return { pos, byId };
}

type Props = {
  graph: Graph;
  highlightNodes: Set<string>;             // node names on the investigated paths
  highlightEdges: Set<string>;             // "from|to" pairs on the investigated paths
  onSelect: (n: GraphNode | null) => void;
};

export default function GraphView({ graph, highlightNodes, highlightEdges, onSelect }: Props) {
  // Asset names currently highlighted by the blast-radius what-if (target + everything it touches)
  const [simulated, setSimulated] = useState<Set<string>>(new Set());
  const [simNote, setSimNote] = useState('');

  const simulate = async (assetName: string) => {
    try {
      const { data } = await api.simulate(assetName);
      setSimulated(new Set([data.target, ...data.impacted]));
      setSimNote(`${data.target}: reaches ${data.reachable.length}, depended on by ${data.dependents.length} (within ${data.depth} hops)`);
    } catch (e) {
      setSimulated(new Set());
      setSimNote((e as Error).message);
    }
  };

  const { nodes, edges } = useMemo(() => {
    const { pos, byId } = layout(graph);
    
    const nodes: Node[] = graph.nodes.map(n => {
      const hot = highlightNodes.has(n.name);
      const isSimulatedImpacted = simulated.has(n.name);
      const color = COLORS[n.type] ?? '#94a3b8';
      const sens = n.type === 'Asset' ? String(n.properties.sensitivity ?? '') : n.type === 'Alert' ? String(n.properties.severity ?? '') : '';
      
      return {
        id: n.id, 
        position: pos.get(n.id) ?? { x: 0, y: 0 }, 
        data: { label: (
          <div style={{ textAlign: 'left' }}>
            <div style={{ font: "9px 'DM Mono'", letterSpacing: '.8px', color, textTransform: 'uppercase' }}>
              {n.type}{sens ? ` · ${sens}` : ''} {isSimulatedImpacted ? '· [SIMULATED IMPACT]' : ''}
            </div>
            <div style={{ fontSize: 12, fontWeight: 600, marginTop: 3 }}>{n.name}</div>
            {n.type === 'Asset' && (
              <button
                className="nodrag nopan"
                onClick={(e) => { e.stopPropagation(); void simulate(n.name); }}
                style={{ marginTop: 6, fontSize: 8, background: '#ef4444', color: '#fff', border: 'none', padding: '2px 6px', borderRadius: 4, cursor: 'pointer' }}
              >
                Simulate blast radius
              </button>
            )}
          </div>) 
        },
        style: {
          background: isSimulatedImpacted ? '#2d1519' : '#0a111e', 
          color: '#e7edf7', 
          border: `1px solid ${isSimulatedImpacted ? '#ef4444' : hot ? '#fb7185' : color + '88'}`, 
          borderRadius: 9,
          padding: '8px 12px', 
          width: 170, 
          boxShadow: isSimulatedImpacted ? '0 0 20px #ef4444aa' : hot ? '0 0 18px #fb718566' : 'none',
        },
      };
    });

    const edges: Edge[] = graph.edges.map(e => {
      const a = byId.get(e.source)?.name ?? '', b = byId.get(e.target)?.name ?? '';
      const hot = highlightEdges.has(`${a}|${b}`);
      const soft = SOFT.has(e.type);
      return {
        id: e.id, source: e.source, target: e.target, label: e.type.replace(/_/g, ' ').toLowerCase(), animated: hot,
        markerEnd: { type: MarkerType.ArrowClosed, color: hot ? '#fb7185' : '#4b6a85' },
        style: { stroke: hot ? '#fb7185' : soft ? '#2f4256' : '#4b6a85', strokeWidth: hot ? 2.4 : 1.4, strokeDasharray: soft ? '5 4' : undefined },
        labelStyle: { fill: '#8da2bb', fontSize: 9 }, labelBgStyle: { fill: '#0c1422' },
      };
    });
    return { nodes, edges };
  }, [graph, highlightNodes, highlightEdges, simulated]);

  return (
    <div className="rf-wrap">
      {simNote && <div style={{ position: 'absolute', zIndex: 5, left: 12, top: 10, fontSize: 11, color: '#fca5a5', background: '#1a0f13cc', border: '1px solid #ef444466', padding: '4px 8px', borderRadius: 6 }}>{simNote}</div>}
      <ReactFlow
        key={graph.nodes.map(n => n.id).join(',') + graph.edges.length}
        nodes={nodes} edges={edges} fitView fitViewOptions={{ padding: 0.15 }} minZoom={0.3}
        nodesConnectable={false} proOptions={{ hideAttribution: true }} colorMode="dark"
        onNodeClick={(_, node) => {
          // You can choose to select the node normally OR trigger simulation on double click/sidebar
          onSelect(graph.nodes.find(n => n.id === node.id) ?? null);
        }}
        onPaneClick={() => {
          onSelect(null);
          setSimulated(new Set()); setSimNote('');
        }}
      >
        <Background color="#1b2a3d" gap={24} />
        <Controls showInteractive={false} />
      </ReactFlow>
    </div>
  );
}