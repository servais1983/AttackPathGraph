# AttackPathGraph

AttackPathGraph is a Python toolkit for building, analyzing, scoring, visualizing, and reporting attack paths from authorized security assessment data.

It ingests common offensive and defensive sources such as Nmap, BloodHound, OpenVAS, and Metasploit, then represents relationships as a directed graph for path analysis, risk scoring, Neo4j export, and web visualization.

> Authorized use only. This project is intended for legitimate penetration tests, security validation, lab training, and defensive exposure management.

## Features

- Import Nmap XML hosts and exposed services.
- Import BloodHound-style JSON relationships.
- Import OpenVAS XML findings.
- Import Metasploit JSON hosts, vulnerabilities, and exploits, plus XML hosts, services, and vulnerabilities.
- Reject unsafe XML entities and expansion attacks in imported scanner files.
- Build a NetworkX directed attack graph.
- Identify entry points, critical assets, and attack paths.
- Score paths and nodes with built-in heuristic risk rules.
- Generate HTML reports, with optional PDF output through WeasyPrint.
- Export graph data to Neo4j.
- Start a Flask web UI for interactive graph exploration.
- Run in Docker with optional Neo4j via Docker Compose.

## Quick Start

```bash
git clone https://github.com/servais1983/AttackPathGraph.git
cd AttackPathGraph
python -m pip install -e ".[dev]"
attackpathgraph --nmap demo/nmap_sample.xml --bh demo/bloodhound_sample.json --ascii
```

Run the tests:

```bash
pytest -q
```

## CLI

```bash
attackpathgraph [OPTIONS]
```

Common options:

| Option | Description |
| --- | --- |
| `--nmap FILE` | Import Nmap XML |
| `--bh FILE` / `--bloodhound FILE` | Import BloodHound JSON |
| `--openvas FILE` | Import OpenVAS XML |
| `--metasploit FILE` | Import Metasploit JSON/XML |
| `--ascii` | Print a simple terminal graph |
| `--analyze` | Analyze attack paths |
| `--score` | Print risk scores |
| `--mitre` | Heuristically map vulnerabilities to MITRE ATT&CK techniques |
| `--report FILE` | Generate `.html` or `.pdf` report |
| `--web` | Start the web UI |
| `--neo4j` | Export to Neo4j |
| `--neo4j-clear` | Clear Neo4j before export |
| `--max-paths N` | Bound attack-path enumeration, default `1000` |
| `--max-path-length N` | Bound path length in edges, default `10` |

Example:

```bash
attackpathgraph \
  --nmap demo/nmap_sample.xml \
  --bh demo/bloodhound_sample.json \
  --analyze \
  --score \
  --report reports/demo.html
```

Path detection, risk scoring, and MITRE ATT&CK mapping are heuristic analysis aids. Validate their output against the source assessment data before using it for security decisions.

## Web UI

```bash
attackpathgraph --nmap demo/nmap_sample.xml --bh demo/bloodhound_sample.json --web
```

By default, the web UI listens on `127.0.0.1:5000`.
In non-debug mode it is served through Waitress.

For containers or remote access:

```bash
export ATTACKPATHGRAPH_AUTH_USERNAME=analyst
export ATTACKPATHGRAPH_AUTH_PASSWORD='replace-with-a-long-random-password'
attackpathgraph --web --host 0.0.0.0 --port 5000 --no-browser
```

Remote binding is refused unless both authentication variables are configured. The web UI uses HTTP Basic authentication, CSRF protection, request-size limits, and per-client rate limiting. Terminate TLS at a trusted reverse proxy and set `ATTACKPATHGRAPH_HTTPS_ONLY=true` when requests reach the application over HTTPS.

Health check:

```bash
curl http://localhost:5000/healthz
```

## Docker

Build and run only the app:

```bash
docker build -t attackpathgraph .
docker run --rm -p 5000:5000 attackpathgraph
```

Run the app with Neo4j:

```bash
cp .env.example .env
# Replace every placeholder secret in .env before starting the stack.
docker compose up --build
```

Neo4j Browser will be available on `http://localhost:7474`.

## Neo4j Export

Set credentials through environment variables:

```bash
export NEO4J_URI=bolt://localhost:7687
export NEO4J_USER=neo4j
export NEO4J_PASSWORD=change-me
attackpathgraph --nmap demo/nmap_sample.xml --neo4j
```

Use `.env.example` as a starting point for local configuration.

Do not commit `.env`. For production, inject secrets through the deployment platform rather than storing them in the Compose file or image.

Existing Neo4j data is preserved by default. Add `--neo4j-clear` only when you explicitly want to wipe the target database before exporting.

The web UI's Neo4j export action is disabled by default. Enable it only for trusted deployments:

```bash
export ATTACKPATHGRAPH_ENABLE_NEO4J_EXPORT=true
```

## PDF Reports

HTML reports work with the base install. PDF reports require WeasyPrint and native system libraries:

```bash
python -m pip install -r requirements-pdf.txt
attackpathgraph --nmap demo/nmap_sample.xml --report reports/demo.pdf
```

If native PDF dependencies are missing, generate HTML instead.

## Development

```bash
python -m pip install -e ".[dev]"
pytest -q
ruff check .
pip-audit -r requirements.txt
```

Project layout:

```text
core/
  analysis/       Attack path and MITRE analysis
  parsers/        Nmap, BloodHound, OpenVAS, Metasploit importers
  reporting/      HTML/PDF report generation
  scoring/        Risk scoring
  security/       Static security review helper
  web/            Flask web interface
demo/             Sample input data
tests/            Regression tests
```

## License

MIT. See `LICENSE`.
