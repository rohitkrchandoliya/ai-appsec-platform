# Roadmap

## Phase 0 — Foundation
- [x] Repository structure
- [x] Domain models
- [x] Scanner interface
- [x] Configuration
- [x] Unit-test foundation
- [x] Docker/CI foundation

## Phase 1 — Deterministic SAST MVP
- [x] Python security scanner foundation
- [x] High-confidence dynamic execution detection
- [x] shell=True command execution detection
- [x] Evidence extraction
- [x] JavaScript/TypeScript security rules
- [x] Finding deduplication
- [x] SARIF 2.1.0 output and CLI flag
- [x] JSON output
- [x] CLI scan command

## Phase 2 — Secrets & Dependencies
- [x] High-confidence secret rules
- [x] Entropy-assisted secret detection
- [x] Python lockfile parsing (`uv.lock`, `poetry.lock`, `Pipfile.lock`)
- [x] OSV advisory integration for exact-pinned Python dependencies
- [x] CycloneDX 1.5 SBOM generation for exact-pinned Python dependencies
- [ ] Dependency risk scoring

## Phase 3 — AI Security Reasoning
- [ ] Provider abstraction
- [ ] Finding explanation
- [ ] Exploitability/context analysis
- [ ] Remediation generation
- [ ] Patch proposal generation
- [ ] Guardrails against hallucinated findings

## Phase 4 — GitHub Developer Workflow
- [ ] GitHub App integration
- [ ] Pull-request scanning
- [ ] Inline findings
- [ ] Security gate
- [ ] Baseline/suppression support
- [ ] Check-run reporting

## Phase 5 — Product Layer
- [ ] API service
- [ ] Web dashboard
- [ ] Project management
- [ ] Historical findings
- [ ] Team workflows
- [ ] Authentication and authorization
- [ ] Usage metering

## Quality gates

Before calling the MVP production-ready:

- meaningful automated test coverage
- deterministic scanner fixtures
- no secrets in repository history
- dependency pinning/lock strategy
- reproducible Docker build
- CI security checks
- documented threat model
- documented limitations and false-positive handling
