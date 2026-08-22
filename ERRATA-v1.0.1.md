# jarsWAF SPEC ERRATA v1.0.1 — BINDING
Precedence: identical to SCHEMAS.md. Every item below corrects a defect found while
materializing the 50 golden vectors. Agents apply these WITHOUT asking.

E-01 GOLDEN VECTOR FIELD SET (finalizes F3 + SCHEMAS §4):
  id, category(sqli|clean), technique, target(query|path|header_ua|cookie|body_form|body_json),
  raw, encoded_variant[](list of additional wire encodings that MUST yield same verdict),
  expect_action(would_block|allow), min_rules[](subset-of fired), notes(optional).
  Scalars: double-quoted (supports \uXXXX,\n,\",\\) or single-quoted (literal, '' escape).
  Loader supports leading `#` comments and inline arrays `[A, B]`.

E-02 TOKENIZER EDGE: an unterminated quote consumes to END OF INPUT as one Str token.
  (Motivating case: benign `name=O'Brien&city=Cork`.)

E-03 SCOPE: ZWSP/Cf-character stripping is OUT of v1.0 pipeline (NFKC preserves U+200B).
  Intra-word ZWSP obfuscation (`sel\u200Bect`) is therefore NOT detected in v1.0 — tracked
  as OQ-004 (enhancement, v1.1 candidate). No vector may assert its detection (H4).

E-04 RULE AMENDMENT SQLI-R002: score 45 -> 55. Predicate gains ALTERNATIVE branch:
  T[i]==Str AND trim(lower(inner)) in {"or","and"} AND T[i+1] in {Str,Num}
  AND T[i+2]==Op("=") AND T[i+3] in {Str,Num} AND inner(T[i+1])==inner(T[i+3]).
  Rationale: quoted tautology `' OR '1'='1` is the canonical injection; structural predicate
  keeps FP rate ~zero. §3 design-intent sentence is REWRITTEN: R002 alone MAY block;
  R005/R007/R008/R009/R011 still cannot block alone. SCHEMAS §6 example event updated:
  hits R002(55)+R010(40), total 95.

E-05 PREDICATE LEXEME RULE: wherever a rule names an identifier-like token
  (sleep, benchmark, pg_sleep, count, mysql, pg_catalog, sqlite_master), the predicate
  matches the token LEXEME regardless of Kw/Ident class. Implement helper
  fn lexeme(t:&Token)->&str. (Defect: KEYWORD_SET contains these words, so prior
  Ident(...) predicates could never fire. Affects R004, R005, R006.)

E-06 VECTOR REALISM CORRECTION: intra-word comment splitting (UNI/**/ON, SL/**/EEP) is
  NOT a viable MySQL bypass — SQL comments parse as whitespace, yielding two identifiers.
  All TECH-001/TECH-006 vectors use INTER-TOKEN comment placement. Intra-word forms are
  documented negative cases (expect allow, notes=intra_word_invalid_sql).

E-07 NUMERIC COMPARISON: R006 compares Num token parsed as u128; unparsable -> no fire.
