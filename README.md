# TraceGuard

**A graph-native security agent whose every decision traces back to its source.**

TraceGuard investigates a security identity over a FalkorDB graph of identities, assets, alerts and evidence. It finds multi-hop attack paths, computes the smallest containment that blocks them, applies it on human approval, and records every action in the graph with the system that asserted each relationship, the investigation that proposed it, and an undo.

Built for **Track 01: Agents That Act on Connected Data**.

> **All data is synthetic.** Graph reachability is not proof of compromise, and this project is not meant to connect to production security systems.

<img width="1542" height="390" alt="image" src="https://github.com/user-attachments/assets/6921fd3b-a689-4ede-8bca-c43cd905bde9" />



## What it does

1. **Triage.** One click scans every identity, ranks them by risk, and shows each one's proposed containment. The scan is read-only.
2. **Investigate.** For one identity the agent runs three timed graph tools: `find_attack_paths` (up to 3 hops across access, network and dependency links), `calculate_blast_radius`, and `retrieve_alert_evidence`. Evidence is scoped to the identity, so another identity's evidence never leaks in.
3. **Explain.** Every hop of every path names the source system that asserted it (for example `synthetic-iam-export`, `synthetic-network-map`). Risk levels come with a stated reason, and a new identity with no access links is reported as "unknown, not safe".
4. **Contain.** From the paths found, the agent computes the smallest set of relationships whose removal blocks every path, plus a network-only alternative that keeps the account's access. Revoking access is the broadest action, and the UI says so.
5. **Act, with a human in control.** Applying a cut removes the relationships, re-runs the investigation, and shows the paths gone and the risk level change.
6. **Remember.** Each investigation is a node in the graph, linked to the identity it examined (`EXAMINED`) and the assets it found paths to (`FOUND_PATH`). Comparisons between runs report changes in paths, assets and risk level, and `GET /memory/asset/{asset}` answers "which investigations found a path to this asset?"
7. **Account for it.** Every applied cut is an `Action` node linked to the investigation that proposed it (`RECOMMENDED`), carrying the source of the removed relationship. Undo restores the relationship with its original source. The audit trail survives a demo graph reset.

<img width="1583" height="927" alt="image" src="https://github.com/user-attachments/assets/29341f67-833d-4ff4-9f46-ca60cb668c52" />
<img width="1582" height="961" alt="image" src="https://github.com/user-attachments/assets/f69f83d7-4856-48ca-934c-3f23a15eda31" />
<img width="912" height="951" alt="image" src="https://github.com/user-attachments/assets/7d5687ba-ae9e-487a-a946-abf11dac825a" />
<img width="1481" height="355" alt="image" src="https://github.com/user-attachments/assets/32269241-6186-4274-b4be-4bdeb5be2215" />
<img width="1911" height="982" alt="image" src="https://github.com/user-attachments/assets/600f97d4-08ba-4e82-8357-d3c5090a522e" />


## Architecture

<img width="1920" height="1080" alt="architecture" src="https://github.com/user-attachments/assets/5bc8b247-d686-4df9-aea4-e4b909045bdf" />


TraceGuard has four parts that all work on one FalkorDB graph.

| Component | Role |
|---|---|
| **Web app** (React + Vite, `:5173`) | Triage queue, investigations, containment, memory and drift, audit trail with undo. |
| **FastAPI backend** (`:8000`) | Runs the agent steps, computes containment, stores memory, records actions. |
| **FalkorDB** (`:6379`) | The single source of truth: the security graph, the saved investigations and the audit trail. |
| **MCP server** (`mcp_server/`, stdio) | Exposes the same tools to any MCP client by calling the running API. |

An optional local LLM (Ollama) writes a short summary of the findings.

### How a request flows

1. The web app, or an MCP client through the MCP server, calls the API.
2. **Triage and investigate** runs three timed graph steps: `find_attack_paths`, `calculate_blast_radius` and `retrieve_alert_evidence`. Each step is a Cypher query against FalkorDB, and every hop it returns carries the `source` of the relationship.
3. **Containment** takes the paths that were found and computes the smallest set of relationships whose removal blocks all of them, plus a network-only alternative. This search runs in Python over the graph results.
4. On human approval, **Actions** removes the relationships and writes one `Action` node per cut, linked to the investigation that proposed it and carrying the edge's original source. Undo restores the relationship from that record.
5. **Memory** saves each run as an `Investigation` node linked to the identity it examined and the assets it found paths to, so later runs can report drift (paths, assets and risk level) and the graph can answer "which investigations found a path to this asset?"
6. If the optional LLM summary is on, the **grounding check** rejects any summary that names an asset, identity or alert that is not in the findings.

### Design decisions

- **One graph for everything.** Facts, memory and the audit trail live in the same database, so a decision can be followed from an action back to the investigation, the path and the system that asserted each link.
- **Deterministic agent, optional model.** The investigation pipeline is fixed and auditable. The language model only summarizes, and it cannot trigger an action.
- **Human in the loop.** Nothing changes the graph without an explicit apply. The MCP `apply_containment` tool only previews unless called with `confirm=true`.
- **Thin MCP layer.** The MCP server holds no logic of its own, so MCP clients and the web app always see the same data and write to the same audit trail.

## Quick start (Windows, Docker Desktop)

```powershell
docker compose up -d --build
```

Open http://localhost:5173. The demo graph seeds itself on first start (use **Reset synthetic demo graph** to restore it).

Suggested walkthrough: **Overview** → **Scan all identities** → **Review & contain** on `elena.rostova` → **Apply cut & re-run** → **Memory & Drift** to see the audit trail and **Undo**.

| Service | URL |
|---|---|
| App | http://localhost:5173 |
| API docs | http://localhost:8000/docs |
| Health (measured DB latency) | http://localhost:8000/health |
| FalkorDB browser | http://localhost:3000 |

The frontend runs from your source folder through a mounted volume. Only the API is built into an image, so after backend changes run `docker compose up -d --build api`.

## How the graph is modelled

- **Nodes:** `Identity`, `Asset`, `Alert`, `Evidence`, plus `Investigation` and `Action` for memory and audit.
- **Edges:** `HAS_ACCESS_TO` (identity to asset), `CONNECTS_TO` and `DEPENDS_ON` (asset to asset), `INVOLVES` and `SUPPORTED_BY` for alerts and evidence. Every edge carries a `source` property naming the system that asserted it.
- **Attack paths** follow access, network and dependency edges forward from an identity to high-sensitivity assets. **Outage simulation** (`POST /graph/simulate`) follows `DEPENDS_ON` in the reverse direction. Both directions are modelling choices, not facts about a real network.

## MCP server

`mcp_server/` exposes TraceGuard's tools over the Model Context Protocol (stdio) so any MCP client can choose among them:

`list_identities`, `triage_identities`, `investigate_identity`, `simulate_impact`, `who_found_paths_to`, `apply_containment`, `list_actions`, `undo_action`.

It wraps the running API, so MCP actions use the same graph, provenance and audit trail as the web app. `apply_containment` only previews unless called with `confirm=true`.

```powershell
cd mcp_server
pip install -r requirements.txt
python smoke_test.py          # lists the tools and calls two of them (the API must be running)
```

Requires the MCP Python SDK 1.x (`mcp<2`; version 2 renamed `FastMCP`). Verified with a stdio client script and the MCP Inspector (`npx @modelcontextprotocol/inspector python server.py`). The server also loads in Claude Desktop through `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "traceguard": {
      "command": "C:\\path\\to\\python.exe",
      "args": ["C:\\path\\to\\traceguard-graph\\mcp_server\\server.py"]
    }
  }
}
```

In the web app the pipeline is fixed by design, for deterministic and auditable runs. Tool selection happens in whichever MCP client connects.

## Optional local LLM summary

Install Ollama on the host and pull a model (`ollama pull qwen2.5:7b`), then tick **Use local Ollama summary**. If Ollama is unavailable, the graph analysis still runs and the response explains the fallback.

A grounding check rejects any summary that names an asset, identity, alert or evidence ID that is not in the findings. It is a heuristic filter against invented names, **not** a check that every claim is correct.

## API

| Endpoint | Purpose |
|---|---|
| `POST /agent/triage` | Read-only scan of every identity, ranked by risk |
| `POST /agent/investigate` | Run and save an investigation |
| `POST /graph/simulate` | What an asset reaches and what depends on it |
| `POST /graph/contain` | Apply a containment cut and record each action |
| `GET /actions` | The audit trail |
| `POST /actions/{id}/undo` | Restore a cut relationship with its original source |
| `DELETE /actions` | Clear the audit trail (demo use) |
| `GET /memory/{identity}`, `POST /memory/compare` | Saved runs and drift |
| `GET /memory/asset/{asset}` | Which saved investigations found a path to this asset |
| `POST /graph/connect`, `POST /graph/disconnect` | Edit relationships (what-if) |
| `POST /graph/identity` | Add an identity explicitly (investigations never invent one) |
| `POST /demo/seed` | Reset the synthetic graph (memory and audit trail are kept) |

Full schema at http://localhost:8000/docs.

## Tests

20 integration tests run against a real FalkorDB, in a separate graph (`traceguard_test`) so demo data is never touched. With the stack running:

```powershell
docker compose exec api python -m pytest -q
```

The test files are copied into the API image at build time, so after editing tests run `docker compose up -d --build api` first. The frontend type-checks and builds with `npm run build` in `frontend/`.

## Known limits

- All data is synthetic and small (a handful of identities and about 17 nodes). It shows the approach, not scale, and it does not import real data.
- The containment cut-set search runs in Python over the paths the graph returns. It is not a database-native algorithm.
- The agent in the web app is a fixed three-step pipeline, and the language model only summarizes. It does not choose tools.
- The grounding check is a heuristic (see above).
- Modelling choices: attack paths treat `DEPENDS_ON` as a route compromise can follow; outage simulation follows it in reverse.
- Reachability is not compromise. A service account that is supposed to reach backups will rank as "medium" and get a proposed cut, which a human reviewer should reject. The agent proposes and the human decides.
- Demo endpoints (`/demo/seed`, connect/disconnect, clearing memory and the audit trail) have no authentication.

## Troubleshooting

- `/health` reports offline: check `docker compose ps` and `docker compose logs api falkordb`.
- A change does not show in the browser: `docker compose restart frontend`, then hard-refresh (`Ctrl+Shift+R`).
- A backend change does not show: rebuild with `docker compose up -d --build api`.
- No nodes: click **Reset synthetic demo graph**.
- Port conflicts: free ports 8000, 5173, 6379 and 3000, or change the mappings in `docker-compose.yml`.
- `pip install` for the MCP server installs version 2: run `pip install "mcp[cli]>=1.2,<2"`.

## Stack

FastAPI, FalkorDB, React with Vite and React Flow, optional Ollama, and an MCP server built on the MCP Python SDK.
