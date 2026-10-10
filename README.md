# AI AppSec Platform

A developer-first application security scanner that combines deterministic source-code and secret checks with normalized findings and machine-readable reports. The longer-term roadmap adds dependency vulnerability intelligence, evidence-grounded AI reasoning, remediation support, GitHub pull-request workflows, and a web dashboard.

## Current implementation

- **Python SAST:** AST-based rules for `eval()` / `exec()` and `subprocess.run(..., shell=True)`.
- **JavaScript/TypeScript SAST:** pattern rules for `eval()`, `new Function()`, `exec()` / `execSync()`, `innerHTML`, and React `dangerouslySetInnerHTML`.
- **Secret detection:** patterns for private-key headers, AWS access key IDs, GitHub tokens, Slack token-like strings, and quoted hardcoded credential assignments. Evidence is redacted by the current secret rules.
- **Dependency inventory:** parses PEP 621 dependencies and optional groups from `pyproject.toml`, requirements files, and exact versions from `uv.lock`, `poetry.lock`, and `Pipfile.lock`. Inventory is included in JSON scan results.
- **Dependency advisory audit:** opt-in `--audit-dependencies` queries the OSV API for exact-pinned Python dependencies and adds known advisories to findings. Network access is required for this option.
- **SBOM export:** `--sbom` emits CycloneDX 1.5 JSON from exact-pinned Python dependencies; unresolved version ranges are intentionally excluded.
- **Finding normalization:** root-relative paths where possible, deterministic sorting, and duplicate removal.
- **CLI reports:** human-readable output, JSON (`--json`), and SARIF 2.1.0 (`--sarif`).
- **Quality checks:** GitHub Actions CI runs Ruff, pytest, and mypy.

This is an early MVP with intentionally limited rule coverage. The JavaScript/TypeScript checks are regex-based, not full semantic or taint analysis. A clean scan does not prove that a repository is secure.

## Quick start

Requires Python 3.12 or newer.

```bash
python -m venv .venv
# Activate the environment for your shell, then:
python -m pip install -e ".[dev]"
```

Run a human-readable scan:

```bash
appsec scan ./path-to-project
```

Export JSON:

```bash
appsec scan ./path-to-project --json
```

Export SARIF 2.1.0:

```bash
appsec scan ./path-to-project --sarif
```

Use `--json` and `--sarif` separately; they cannot be combined in one invocation.

## How it works

1. The CLI accepts a project directory.
2. Python, JavaScript/TypeScript, and secret scanners inspect supported files.
3. Findings are normalized, sorted, and deduplicated.
4. The CLI prints human-readable results or exports JSON/SARIF.
5. Planned layers will add dependency advisory analysis, evidence-grounded AI explanations and remediation proposals, GitHub PR/check-run integration, and a web API/dashboard.

## Engineering principles

1. Prefer high-confidence deterministic detection over AI-only vulnerability claims.
2. Every finding should have a reproducible rule identifier and source location.
3. Treat scanned source code as untrusted data.
4. Do not export raw secret evidence in machine-readable reports.
5. Never commit credentials, API keys, tokens, or private customer data.
6. Test scanners as security-critical software and document limitations.

## Roadmap

See [ROADMAP.md](ROADMAP.md) for the implementation plan and production-readiness gates.

## Current limitations

- Detection coverage is narrow and rule-based.
- JavaScript/TypeScript analysis is regex-based and may produce false positives or miss indirect/obfuscated cases.
- Secret patterns do not cover every provider, token type, encoding, or credential storage pattern.
- Dependency advisory lookup is available for exact-pinned Python versions through OSV, and CycloneDX 1.5 SBOM export is implemented for exact-pinned Python dependencies; dependency risk scoring, AI reasoning/remediation, GitHub PR integration, API, dashboard, authentication, and team workflows are not implemented yet.
- Production readiness requires broader fixtures and coverage, dependency locking/auditing, a documented threat model, reproducible builds, and repository governance.

## License

The project metadata declares MIT licensing. A license file should be included in the repository before distributing it as an MIT-licensed project.
