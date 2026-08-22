# jarsWAF Agent Kickoff (paste as first message to ANY coding agent)

You are implementing the jarsWAF repository from a LOCKED specification suite.
Repository: https://github.com/Azhar457/jarswaf (work on a feature branch).

MANDATORY READ ORDER before writing any code:
1. llms.txt          2. AGENTS.md        3. ERRATA-v1.0.1.md
4. TASKS.md          5. PRD.md           6. SCHEMAS.md      7. ARCHITECTURE.md

EXECUTION CONTRACT:
- Execute tasks strictly sequentially starting at the first incomplete task.
- After EVERY task run the gate:
  cargo fmt --check && cargo clippy --workspace --all-targets --all-features -- -D warnings && cargo test --workspace
  Gate red => fix before proceeding. Never edit tests to pass (H4).
- Precedence on conflicts: SCHEMAS > ERRATA > ARCHITECTURE > PRD > TASKS.
- Any ambiguity/conflict/blocker: STOP, append OQ entry to OPEN_QUESTIONS.md per
  AGENTS.md Stop Protocol. Do NOT guess, do NOT improvise APIs, routes, names, numbers.
- Hard rules H1–H15 in AGENTS.md are absolute. Dependency whitelist there is closed.
- Finish each task with the completion-report block defined in AGENTS.md.
