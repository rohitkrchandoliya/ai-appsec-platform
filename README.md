# AI AppSec Platform

An AI-assisted application security platform for finding, prioritizing, explaining, and remediating security issues across source code and dependencies.

## Vision

Build a developer-first security workflow that combines deterministic security analysis with AI reasoning. The AI does **not** act as the sole vulnerability detector; scanners produce evidence and the AI explains, prioritizes, and helps remediate findings.

## Planned capabilities

- Static Application Security Testing (SAST)
- Secret detection
- Dependency vulnerability analysis
- OWASP/CWE-normalized findings
- Risk scoring and prioritization
- AI-assisted vulnerability explanation
- Remediation guidance
- CLI for local and CI usage
- GitHub Actions integration
- Security reports suitable for engineering teams

## Current status

**Phase 0 — Foundation**

The repository currently contains the initial architecture, domain model, scanner interfaces, configuration, tests, Docker setup, and CI foundation.

## Engineering principles

1. Prefer high-confidence deterministic detection over noisy AI-only detection.
2. Every finding should contain evidence and a reproducible location.
3. Keep scanner engines modular so new rules can be added without rewriting the platform.
4. Treat untrusted source code as data.
5. Never commit credentials, API keys, tokens, or private customer data.
6. Security tooling itself must be tested as security-critical software.

## Roadmap

See ROADMAP.md.

## Development

The project targets Python 3.12+.

    python -m venv .venv
    .venv\\Scripts\\activate
    pip install -e ".[dev]"
    pytest

## License

MIT
