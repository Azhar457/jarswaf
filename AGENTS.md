# jarsWAF — Agent Operating Contract v1.0

You are an autonomous coding agent. This contract SUPERSEDES your general defaults.
Prime directive: implement EXACTLY what TASKS.md specifies, using ONLY names/numbers defined in
ARCHITECTURE.md + SCHEMAS.md. When documents disagree, precedence: SCHEMAS > ERRATA > ARCHITECTURE > PRD > TASKS.

## Startup sequence (every session)
1. Read llms.txt. 2. Read AGENTS.md (this). 3. Read TASKS.md, find first incomplete task.
4. Read sections of PRD/ARCHITECTURE/SCHEMAS/ERRATA referenced by that task. 5. Implement.

## Hard rules (violations = failed work regardless of tests passing)
H1 SCOPE LOCK: touch only files the current task lists (plus their tests).
H2 NAME LOCK: every public symbol/file/route/metric/log-key uses the exact identifier from ARCHITECTURE/SCHEMAS.
H3 NUMBER LOCK: thresholds, sizes, timeouts, scores, ports come from SCHEMAS/config defaults.
H4 TEST SANCTITY: never modify/delete/skip a test to make it pass.
H5 DEPENDENCY LOCK: only whitelist below. Need something else? Stop Protocol.
H6 PANIC DISCIPLINE: no unwrap()/expect()/panic! in src/ outside tests.
H7 UNSAFE DISCIPLINE: unsafe only in waf-kernel/ebpf glue with // SAFETY: comments.
H8 NO STUBS: no todo!(), unimplemented!(), empty impls, placeholder strings pretending to work.
H9 CONVENTIONAL COMMITS: type(scope): summary + body citing task id + FR ids.
H10 ONE TASK ONE BRANCH: branch feat/<task-id>-<slug>.
H11 GATE BEFORE DONE: task complete ONLY when fmt+clippy+test all green locally AND in CI.
H12 NO NETWORK AT BUILD/RUN beyond cargo index fetch.
H13 SECRETS: never log or commit passwords, hashes, session tokens, or admin.hash contents.
H14 PLATFORM: linux-specific code behind cfg(target_os="linux").
H15 LANGUAGE: code identifiers/comments/docs in English.

## Stop Protocol (ambiguity/conflict/blockers)
1. Halt the task immediately. Do not guess.
2. Append entry to OPEN_QUESTIONS.md.
3. Commit open-questions entry.
4. If another independent task exists, proceed; else stop session with status summary.
