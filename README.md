# AttackPathGraph

AttackPathGraph is a Python toolkit for building, analyzing, scoring, visualizing, and reporting attack paths from authorized security assessment data.

It ingests common offensive and defensive sources such as Nmap, BloodHound, OpenVAS, and Metasploit, then represents relationships as a directed graph for path analysis, risk scoring, Neo4j export, and web visualization.

> Authorized use only. This project is intended for legitimate penetration tests, security validation, lab training, and defensive exposure management.

## Features

- Import Nmap XML hosts and exposed services.
- Import BloodHound-style JSON relationships.
- Import OpenVAS XML findings.
- Import Metasploit JSON/XML hosts, vulnerabilities, and exploits.
- Build a NetworkX directed attack graph.
- Identify entry points, critical assets, and attack paths.
- Score paths and nodes by risk.
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
| `--mitre` | Map vulnerabilities to MITRE ATT&CK techniques |
| `--report FILE` | Generate `.html` or `.pdf` report |
| `--web` | Start the web UI |
| `--neo4j` | Export to Neo4j |
| `--neo4j-clear` | Clear Neo4j before export |

Example:

```bash
attackpathgraph \
  --nmap demo/nmap_sample.xml \
  --bh demo/bloodhound_sample.json \
  --analyze \
  --score \
  --report reports/demo.html
```

## Web UI

```bash
attackpathgraph --nmap demo/nmap_sample.xml --bh demo/bloodhound_sample.json --web
```

By default, the web UI listens on `127.0.0.1:5000`.
In non-debug mode it is served through Waitress.

For containers or remote access:

```bash
attackpathgraph --web --host 0.0.0.0 --port 5000 --no-browser
```

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

Existing Neo4j data is preserved by default. Add `--neo4j-clear` only when you explicitly want to wipe the target database before exporting.

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
