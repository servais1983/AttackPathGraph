# Security Policy

AttackPathGraph is dual-use security software. Use it only on systems where you have explicit authorization.

## Supported Versions

Security fixes target the `main` branch.

## Reporting a Vulnerability

Please report vulnerabilities privately to the repository owner before public disclosure. Include:

- Affected version or commit.
- Reproduction steps.
- Impact and exploitability notes.
- Suggested remediation, if available.

Do not include real third-party target data in reports.

## Deployment Baseline

- Do not expose the web UI without `ATTACKPATHGRAPH_AUTH_USERNAME` and `ATTACKPATHGRAPH_AUTH_PASSWORD`.
- Put the service behind HTTPS and set `ATTACKPATHGRAPH_HTTPS_ONLY=true`.
- Keep Neo4j and its Bolt port on a private network unless remote access is explicitly required.
- Leave web-triggered Neo4j export disabled unless the deployment is trusted.
- Inject secrets at runtime and rotate them after any suspected disclosure.
- Run `pip-audit -r requirements.txt` and the test suite before releases.
