# jarsWAF Schemas v1.0 — CANONICAL NUMBERS (override all prose)

## §1 config.example.toml (byte-canonical)
[general]
mode = "detect"                      # detect | enforce
[proxy]
listen = "0.0.0.0:8080"
upstream = "http://127.0.0.1:9000"
max_inspect_bytes = 65536
request_timeout_ms = 30000
connect_timeout_ms = 5000
[block_action]
status = 403
body_html = "<html><body><h1>403 Forbidden</h1><!-- jarsWAF --></body></html>"
send_rst = false
[detection]
block_threshold = 50
max_decode_iterations = 5
[dashboard]
listen = "127.0.0.1:9443"
session_ttl_sec = 28800
login_max_attempts = 5
login_window_sec = 900
[logging]
file_path = "/var/log/jarswaf/events.jsonl"
max_file_mb = 100
max_files = 10
[xdp]
enabled = true
interface = "eth0"
protected_ports = [8080]
trusted_cidrs = ["127.0.0.0/8", "10.0.0.0/8", "192.168.0.0/16"]
syn_rate_limit_per_min = 100
ban_seconds = 60
[latency]
enabled = true
window_sec = 60
delta_alert_ms = 250

Admin password NOT in config: stored hashed in /etc/jarswaf/admin.hash (Argon2id PHC string),
created by install.sh via scripts/gen-password-hash.sh; chmod 600 owner root.

## §2 Tokenizer grammar
Post-lowercase scan. Order: whitespace skip; '...' or "..." or `...` => Str(inner, '' escape);
[0-9.]+ => Num; [a-z_]+ => Kw(KEYWORD_SET) if member else Ident;
ops longest-first: <=>,<=,>=,<>,!=,|| => Op; singles =<>+-*/%;,(). => Op/Punct;
any other byte: skip silently. KEYWORD_SET =
select union all distinct from where and or not null as insert into values update set delete
drop truncate alter create with recursive by order group having limit offset join inner left
right outer on exists between like in is case when then else end asc desc information_schema
waitfor delay exec execute declare cast convert concat substring ascii char hex unhex
load_file outfile dumpfile count sum min max sleep benchmark pg_sleep.

## §3 RuleRegistry (frozen; adding/removing = PRD amendment)
Evaluation inputs: tokens T, meta M, raw_lower R (lowercased pre-comment-strip original).
Score = sum(rule scores fired) per target. WouldBlock iff Score >= threshold(50).

SQLI-R001 65  EXISTS i: T[i]==Kw("union") AND EXISTS j>i, j<=i+3: T[j]==Kw("select")
SQLI-R002 55  (EXISTS i: T[i] in {Kw(or),Kw(and)} AND T[i+1] in {Str,Num} AND T[i+2]==Op("=")
              AND T[i+3] in {Str,Num} AND T[i+1].inner == T[i+3].inner)
              OR (EXISTS i: T[i]==Str AND trim(lower(inner)) in {"or","and"} AND T[i+1] in {Str,Num}
              AND T[i+2]==Op("=") AND T[i+3] in {Str,Num} AND inner(T[i+1])==inner(T[i+3]))
SQLI-R003 60  EXISTS i: T[i]==Punct(";") AND EXISTS j>i, j<=i+2:
              T[j]==Kw in {delete drop insert update truncate alter create}
SQLI-R004 70  EXISTS i: (lexeme(T[i]) in {"sleep","benchmark","pg_sleep"} AND T[i+1]==Punct("("))
              OR (lexeme(T[i])=="waitfor" AND lexeme(T[i+1])=="delay")
SQLI-R005 30  EXISTS i: lexeme(T[i])=="information_schema"
              OR lexeme(T[i]) in {"mysql","pg_catalog","sqlite_master"}
SQLI-R006 55  EXISTS i<j: lexeme(T[i])=="with" AND lexeme(T[j])=="recursive" AND EXISTS lexeme(T[k])=="count"
              followed-by Punct("(") AND EXISTS Num(n) with numeric_value >= 100000
SQLI-R007 25  M.comment_count >= 3
SQLI-R008 35  EXISTS vc in M.version_comments: vc.lowercase CONTAINS ANY OF
              ["select","union"," or "," and "]
SQLI-R009 20  COUNT(T==Kw(from)) >= 4 AND NOT EXISTS Kw(where)
SQLI-R010 40  EXISTS i: T[i]==Str AND T[i+1] in {Kw(or),Kw(and)} AND T[i+2]==Str
SQLI-R011 10  COUNT(T==Kw(any)) >= 15

Design intent: R001, R002, R003, R004, R006 fire alone-block; R005, R007, R008, R009, R011
alone stay below 50 (false-positive safety); combos cross threshold.

## §4 Golden vectors format
Format fields: id, category, technique, target, raw, encoded_variant[], expect_action, min_rules[], notes.

## §5 API contract (base http://127.0.0.1:9443; auth=cookie unless noted)
GET  /login                  -> 200 HTML form (no auth)
POST /login                  -> form username,password; success 303 Location:/ + Set-Cookie;
                                bad creds 401; limited 429
POST /logout                 -> 303 /login; revoke session
GET  /                       -> 200 HTML dashboard
GET  /api/v1/stats           -> 200 {"requests_total":u64,"allowed":u64,"would_block":u64,
                                   "blocked":u64,"inspect_skipped":u64,"engine_errors":u64,
                                   "active_rules":u32,"uptime_sec":u64,
                                   "xdp":{"enabled":bool,"dropped_total":u64}}
GET  /api/v1/events/stream   -> text/event-stream; retry:15000; heartbeats ":hb" every 15s
GET  /api/v1/rules           -> [{"id":"SQLI-R001","score":65,"enabled":true},...] (11 items)
PATCH /api/v1/rules/{id}     -> body {"enabled":bool}; 200 {"id":"..","score":n,"enabled":b};
                                unknown id 404 {"error":"unknown_rule"}
GET  /metrics                -> Prometheus text (no auth, loopback only)
Errors uniform: 401 {"error":"unauthorized"} 429 {"error":"rate_limited"}

## §6 Log event schema (JSON Lines; keys exact)
Base: @timestamp(RFC3339 nanos), ecs.version:"8.11.0", event.dataset:"jarswaf.waf",
event.id(uuid4), req_id(hex16), event.kind:"alarm"|"metric",
event.category:["web"]|["intrusion_detection"].
Decision adds: event.action in {allow,would_block,block_rst,inspect_skipped,engine_error,
latency_anomaly,xdp_unavailable}, source.ip, source.port, http.request.method, url.path,
url.query (<=2048B truncated), user_agent.original (<=512B truncated),
jarswaf.target (which surface), jarswaf.score.total u32, jarswaf.score.threshold u32,
jarswaf.rule.hits [{"rule_id","score"}...], jarswaf.decode.iterations u8,
jarswaf.decode.hit_cap bool, jarswaf.comment.count u32, jarswaf.skip.reason?.
xdp aggregate (1/min): event.action:"xdp_drop_aggregate", jarswaf.xdp.dropped u64,
jarswaf.xdp.banned_active u64.

## §7 Metrics (exact names)
jarswaf_requests_total{decision=allow|would_block|block|skipped|error} COUNTER
jarswaf_rule_hits_total{rule_id} COUNTER
jarswaf_upstream_errors_total COUNTER
jarswaf_inspect_duration_seconds SUMMARY (quantiles 0.5,0.95,0.99; max_age 60s)
jarswaf_origin_latency_p99_ms GAUGE
jarswaf_baseline_latency_p99_ms GAUGE
jarswaf_xdp_dropped_total COUNTER
jarswaf_xdp_banned_ips GAUGE
jarswaf_active_sessions GAUGE
jarswaf_sse_subscribers GAUGE
jarswaf_events_dropped_broadcast_total COUNTER
