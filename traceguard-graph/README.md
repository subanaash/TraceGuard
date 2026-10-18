# TraceGuard — Graph-native security investigation demo

TraceGuard is a local hackathon demo for explainable graph investigations and persistent cross-run memory. It uses FastAPI, FalkorDB, React/Vite, and optionally Ollama for a cautious natural-language summary.

**All seeded identities, alerts, evidence, and infrastructure are synthetic.** This project does not prove compromise and is not intended to connect to production security systems.
The demo data loads automatically on first start. Open Investigations, pick elena.rostova, and run it.
## Run on Windows

1. Install Docker Desktop and start it.
2. In PowerShell, change directory to this folder (`traceguard`).
3. Start all services:

   ```powershell
   docker compose up -d --build
   ```

4. Open http://localhost:5173
5. The demo graph seeds itself on first start (use **Reset demo graph** to restore it).
6. Open Investigations and run `elena.rostova`.

API docs: http://localhost:8000/docs  
Health: http://localhost:8000/health  
FalkorDB browser: http://localhost:3000

## Optional local Ollama

Install Ollama on the host and pull a model, e.g. `ollama pull qwen2.5:7b`. The compose default points to `host.docker.internal:11434`. In the investigation view, enable **Use local Ollama summary**. If Ollama is unavailable, graph analysis still runs and the response explains the fallback.

## Core capabilities

- Synthetic graph seeding and visualization
- Graph-grounded multi-hop path discovery and source provenance
- Alert/evidence retrieval and simple blast-radius analysis
- Persistent investigation records stored in FalkorDB
- Cross-run comparison of assets and paths
- Blast-radius what-if on any asset (`POST /graph/simulate`): what it reaches and what depends on it
- Explicit identity creation (`POST /graph/identity`); investigations never invent identities
- Export of the on-screen investigation as JSON, including per-hop provenance
- Optional Ollama summary

## Test

```powershell
docker compose run --rm --build api pytest -v tests
```

Tests require the Compose FalkorDB service to be running. If starting fresh, run `docker compose up -d falkordb` first.

## Troubleshooting

- `health` reports offline: check `docker compose ps` and `docker compose logs api falkordb`.
- No nodes: click **Seed / reset synthetic demo data** in the dashboard.
- Frontend blank: check browser console and `docker compose logs frontend`.
- API port conflicts: free ports 8000, 5173, 6379, and 3000 or change the mappings in `docker-compose.yml`.
