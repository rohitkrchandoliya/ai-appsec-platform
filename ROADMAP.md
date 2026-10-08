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
- [x] CWE/OWASP mapping
- [ ] JavaScript/TypeScript security rules
- [ ] Finding deduplication
- [ ] SARIF output
- [ ] JSON output
- [ ] CLI scan command

## Phase 2 — Secrets & Dependencies
- [ ] High-confidence secret rules
- [ ] Entropy-assisted secret detection
- [ ] Lockfile parsing
- [ ] Dependency advisory integration
- [ ] SBOM generation
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
