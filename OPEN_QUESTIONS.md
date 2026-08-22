# jarsWAF OPEN QUESTIONS
Protocol (AGENTS.md Stop Protocol): halt task -> append entry -> commit
`docs(open-questions): add OQ-NNN blocking <task-id>` -> proceed only if another
independent task exists. Decisions belong to the maintainer; agents NEVER self-resolve
entries marked blocking.

## Index
| ID     | Title                          | Status   | Decision |
|--------|--------------------------------|----------|----------|
| OQ-001 | Dashboard stack: htmx vs Svelte| RESOLVED | (A) Server-rendered + htmx |
| OQ-002 | Production port scheme         | RESOLVED | (A) Default 8080, systemd capabilities for 80/443 |
| OQ-003 | aya pin: 0.13.1 vs 0.14.0      | RESOLVED | (A) Pin exact 0.13.1 |
| OQ-004 | Cf-strip normalization stage   | OPEN     | Post-v1.0 enhancement |

### OQ-001 dashboard-stack
- Decision: Option A (server-rendered + htmx, vendored zero node dependency).

### OQ-002 production-port-scheme
- Decision: Option A (default listen 8080 in config.toml; CAP_NET_BIND_SERVICE for 80/443 in production).

### OQ-003 aya-pin-version
- Decision: Option A (pin exact 0.13.1 for ABI boundary stability).

### OQ-004 cf-strip-stage (NON-BLOCKING)
- Task: none (post-MVP)
- Status: OPEN for v1.1 candidate.
