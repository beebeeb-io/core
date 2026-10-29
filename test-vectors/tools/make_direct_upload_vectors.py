"""test-vectors/direct_upload.json: the upload answer parsers and the per-chunk policy (task 2173, core PR C).

Hand-authored from the spec (R1.1, R1.6, R2.4, R2.6, R3.1, R3.4) and the server's real bodies (server main 30c8ed62, routes/direct_transfer.rs).
The policy waits that carry jitter are computed here by an independent port of the jitter rule (splitmix64 seed, xorshift64*, equal
jitter), not by running the Rust code.
usage: python3 make_vectors_upload.py <out.json>
"""
import json
import os
import sys

sys.dont_write_bytecode = True  # no __pycache__ next to the scripts
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

API_PROD = "https://api.beebeeb.test"
API_DEV = "http://localhost:3001"

discoveries = {
    "std": {"download": ["object-download-v1"], "upload": ["object-upload-v1"], "storage_hosts": ["s3.storage.test"],
            "storage_buckets": [{"host": "s3.storage.test", "bucket": "bb-01"}], "max_window": 32, "url_ttl_seconds": 300},
    "dev": {"download": [], "upload": ["object-upload-v1"], "storage_hosts": ["localhost:9000"],
            "storage_buckets": [{"host": "localhost:9000", "bucket": "bb-dev"}], "max_window": 32, "url_ttl_seconds": 300},
}

LINK = "https://s3.storage.test/bb-01/tenants/t/files/f/versions/v/staging/3/g.bin?X-Amz-Signature=SIG"


def grant(index=3, transport="object-upload-v1", method="PUT", url=LINK, headers=None, expires="2027-01-15T08:05:00Z", skipped=None, drop=()):
    body = {"transport": transport, "index": index}
    if skipped is not None:
        body["skipped"] = skipped
    else:
        body["method"] = method
        body["url"] = url
        body["headers"] = {"content-type": "application/octet-stream"} if headers is None else headers
        body["expires_at"] = expires
    for key in drop:
        body.pop(key, None)
    return json.dumps(body, separators=(",", ":"))


grant_answers = []


SYNTHETIC = "synthetic: a server (or a proxy) that breaks the contract; the client must refuse it"
ACCEPT = "synthetic: a variation the client accepts (it is not an error)"
RS = "server 30c8ed62 beebeeb-api/src/"


def g(name, body, expect, index=3, api="prod", disc="std", src=SYNTHETIC):
    grant_answers.append({"name": name, "index": index, "api_base": api, "discovery": disc, "body": body, "expect": expect, "source": src})


LINK_EXPECT = {"kind": "link", "index": 3, "content_type": "application/octet-stream"}
g("the server's grant", grant(), LINK_EXPECT, src=RS + "routes/direct_transfer.rs:895-902 (upload_grant); tests/direct_upload_2173.rs:402-403")
g("a skipped chunk carries no link (R1.1)", grant(skipped=True), {"kind": "skipped"}, src=RS + "routes/direct_transfer.rs:700 (a chunk already recorded); tests/direct_upload_2173.rs:505")
g("a header name in another case", grant(headers={"Content-Type": "application/octet-stream"}), LINK_EXPECT, src=ACCEPT)
g("dev: http to the local MinIO", grant(url="http://localhost:9000/bb-dev/k?X-Amz-Signature=SIG"), {"kind": "link", "index": 3, "content_type": "application/octet-stream"}, api="dev", disc="dev", src=ACCEPT)
g("not json", "{nope", {"kind": "violation", "code": "malformed"})
g("an array", "[]", {"kind": "violation", "code": "malformed"})
g("an empty object", "{}", {"kind": "violation", "code": "malformed"})
g("another transport", grant(transport="object-upload-v2"), {"kind": "violation", "code": "transport"})
g("the api transport", grant(transport="api"), {"kind": "violation", "code": "transport"})
g("another chunk", grant(index=4), {"kind": "violation", "code": "index"})
g("a GET", grant(method="GET"), {"kind": "violation", "code": "method"})
g("no method", grant(drop=("method",)), {"kind": "violation", "code": "method"})
g("no url", grant(drop=("url",)), {"kind": "violation", "code": "malformed"})
g("an extra header", grant(headers={"content-type": "application/octet-stream", "x-amz-acl": "public-read"}), {"kind": "violation", "code": "headers"})
g("another content type", grant(headers={"content-type": "text/html"}), {"kind": "violation", "code": "headers"})
g("an authorization header", grant(headers={"authorization": "Bearer x"}), {"kind": "violation", "code": "headers"})
g("no headers", grant(headers={}), {"kind": "violation", "code": "headers"})
g("an unreadable expiry", grant(expires="tomorrow"), {"kind": "violation", "code": "expiry"})
g("no expiry", grant(drop=("expires_at",)), {"kind": "violation", "code": "expiry"})
g("a host that is not listed", grant(url=LINK.replace("s3.storage.test", "evil.test")), {"kind": "violation", "code": "authority_host_not_listed"})
g("a bucket that is not listed", grant(url=LINK.replace("/bb-01/", "/other/")), {"kind": "violation", "code": "authority_bucket_not_listed"})
g("plain http to a public host", grant(url=LINK.replace("https://", "http://")), {"kind": "violation", "code": "authority_not_https"})
g("userinfo in the link", grant(url=LINK.replace("https://", "https://evil@")), {"kind": "violation", "code": "authority_userinfo"})
g("an IP literal", grant(url="https://203.0.113.9/bb-01/k?X-Amz-Signature=SIG"), {"kind": "violation", "code": "authority_ip_literal"})

commit_answers = []


def k(name, body, expect, index=3, size=4194332, src=SYNTHETIC):
    commit_answers.append({"name": name, "index": index, "size": size, "body": body, "expect": expect, "source": src})


k("the server's commit", '{"index":3,"size":4194332,"skipped":false,"object_key":"tenants/t/files/f/versions/v/3.bin"}', {"kind": "committed", "skipped": False}, src=RS + "routes/direct_transfer.rs:1137 (commit_locked); tests/direct_upload_2173.rs:472")
k("a repeated commit is skipped (R1.1)", '{"index":3,"size":4194332,"skipped":true,"object_key":"tenants/t/files/f/versions/v/3.bin"}', {"kind": "committed", "skipped": True}, src=RS + "routes/direct_transfer.rs:1000-1001 (skipped_commit); tests/direct_upload_2173.rs:496")
k("no skipped field", '{"index":3,"size":4194332}', {"kind": "committed", "skipped": False}, src=ACCEPT)
k("another chunk", '{"index":4,"size":4194332,"skipped":false}', {"kind": "violation", "code": "index"})
k("another size", '{"index":3,"size":4194331,"skipped":false}', {"kind": "violation", "code": "size"})
k("not json", "{nope", {"kind": "violation", "code": "malformed"})
k("an empty object", "{}", {"kind": "violation", "code": "malformed"})
k("an array", "[]", {"kind": "violation", "code": "malformed"})

# Numbers the server fixes and a client must agree with. A client cannot import them; this file is the shared record,
# and the core tests pin the client's constants to it. The server's side of the pin is one assert (see core PR C).
constants = {
    "max_grants_per_chunk": 4,
    "max_grants_per_chunk_source": RS + "direct_transfer.rs:402 (MAX_GRANTS_PER_CHUNK), enforced at routes/direct_transfer.rs:770-775; tests/direct_upload_2173.rs:1475 (the fifth grant is a 429, x-ratelimit-limit 4)",
    "content_type": "application/octet-stream",
    "content_type_source": RS + "direct_transfer.rs:395 (CHUNK_CONTENT_TYPE), routes/direct_transfer.rs:900; tests/direct_upload_2173.rs:403",
    "commit_lock_ttl_seconds": 420,
    "commit_lock_ttl_source": RS + "direct_transfer.rs:410-412 (commit_lock_secs() = 4 * s3_op_timeout_secs() + 60), storage.rs:1952-1958 (s3_op_timeout_secs() = 90 unless S3_PUT_OP_TIMEOUT_SECS); the lock is held for its whole TTL after a copy was issued: routes/direct_transfer.rs:1079-1086 (mutation_issued .. mutation_settled, R3.1)",
    # Clients plan A2: the server numbers the client time bounds must fit under (the late-write fence of a PUT), then the bounds.
    "url_ttl_seconds": 300,
    "url_ttl_seconds_source": RS + "direct_transfer.rs:33 (URL_TTL_SECS); the shortest link a server issues is MIN_URL_LIFETIME_SECS = 60 (:36)",
    "put_allowance_floor_seconds": 300,
    "put_allowance_floor_seconds_source": RS + "direct_transfer.rs:399 (PUT_ALLOWANCE_SECS), used by put_allowance_secs() at :434-437 = max(300, ceil(length * 8 / min_uplink_bps) + 60)",
    "upload_lease_seconds": 3600,
    "upload_lease_seconds_source": RS + "upload_lease.rs:151 (DEFAULT_LEASE_SECS); min_uplink_bps_for_chunk() at :248 = ceil(chunk_bytes * 8 / lease_secs), applied to the largest chunk by direct_transfer.rs:424-429 (min_uplink_bps)",
    "max_ciphertext_chunk_bytes": 268435484,
    "max_ciphertext_chunk_bytes_source": RS + "routes/files.rs:98-100 (max_ciphertext_chunk_bytes(u64::MAX)); asserted as 256 * MIB + 28 at routes/files.rs:8130",
    "storage_connect_timeout_seconds": 15,
    "storage_get_idle_seconds": 30,
    "discovery_timeout_seconds": 15,
    "api_call_timeout_seconds": 60,
    "background_put_resource_timeout_seconds": 240,
    "storage_total_base_seconds": 60,
    "storage_total_bytes_per_second": 131072,
    "client_timeouts_source": "client policy: docs/superpowers/specs/2026-10-25-direct-transfer-clients-design.md 6.2 (the per-stack bounds) and 6.3 (the invariants that tie them to the server numbers above); background_put_resource_timeout_seconds is review BL1 (a start as late as link expiry must end before the allowance floor, 300 - 60)",
}

INIT_SRC = RS + "routes/uploads.rs:789-792 (direct_wanted: the flag, the declared token, no upload cap, a live Redis; only then does the 201 carry transport = object-upload-v1); core wire.rs upload_init_selects_direct"
init_transport = [
    {"name": "the server selected direct", "field": "object-upload-v1", "direct": True, "source": INIT_SRC},
    {"name": "no transport field: today's chunk PUT route", "field": None, "direct": False, "source": INIT_SRC + "; an old server, or a flag that is off, sends none"},
    {"name": "any other value: today's chunk PUT route", "field": "api", "direct": False, "source": "client-side case: no server sends it; the rule is that only the exact token selects direct"},
    {"name": "a transport nobody asked for", "field": "object-upload-v2", "direct": False, "source": "client-side case: a future server; the rule is that only the exact token selects direct"},
    {"name": "another case", "field": "Object-Upload-V1", "direct": False, "source": "client-side case: the token is compared exactly"},
]

policy = []
GR, PU, CO = "upload_grant", "put", "upload_commit"
from jitter_port import Rng, Sim  # noqa: E402  (the independent port of core's jitter rule)


def retry(ms, call):
    return {"kind": "retry", "millis": ms, "call": call}


USE_API = {"kind": "use_api"}
BACKOFF = lambda ms: {"kind": "backoff", "millis": ms}
HELD = lambda ms: {"kind": "held", "millis": ms}
RETRY = {"kind": "retry"}
T403 = {"kind": "terminal", "status": 403, "error": "forbidden"}


def fail(where, what, expect, repeat=None):
    f = {"kind": where}
    if where == "put":
        f["status"] = what
    else:
        f["outcome"] = what
    step = {"op": "failed", "failure": f, "expect": expect}
    if repeat:
        step["repeat"] = repeat
    return step


issued = {"op": "link_issued"}
may = lambda yes: {"op": "may_ask", "expect": yes}


POL = "client policy (core's UploadChunkState; no server body): "
POLICY_SOURCES = [  # (a word in the scenario name, where the rule comes from)
    ("hold", POL + "the server's commit lock: " + RS + "direct_transfer.rs:410-412 (commit_lock_secs = 4 * 90 s + 60 s) and routes/direct_transfer.rs:1079-1086 (the lock is held from the copy's issue to its TTL, R3.1); the client waits it out on an allowance of its own"),
    ("jitter", POL + "spec R4 'exponential backoff and jitter'; the jittered waits are computed by test-vectors/tools/jitter_port.py, not by running the Rust"),
    ("fourth link", POL + "the server's 4-grant cap: " + RS + "direct_transfer.rs:402 (MAX_GRANTS_PER_CHUNK), enforced at routes/direct_transfer.rs:770-775 (R2.4); spec R4 doubling backoff with jitter (jitter_port.py)"),
    ("granted again", POL + "the server's 4-grant cap: " + RS + "direct_transfer.rs:402 (MAX_GRANTS_PER_CHUNK, R2.4); a chunk_not_stored commit means nothing was committed (routes/direct_transfer.rs:906-908)"),
    ("budget", POL + "spec R2.6 bounded retries: 150 s of waiting in all; stated waits are the server's (the limiter's Retry-After, rate_limit.rs:2028-2041)"),
    ("eighth failure", POL + "spec R2.6 bounded retries: the 8th failure ends the tries (7 are ridden out)"),
    ("seven retries", POL + "spec R2.6 bounded retries and R4 backoff with jitter (jitter_port.py)"),
    ("authorization", POL + "spec R1.6: an authorization answer is terminal, never a fallback (server error.rs:1012-1013)"),
    ("gone", POL + "spec R1.6: a JSON 404 is the session being gone, which the caller's session recovery owns (server error.rs:1008)"),
    ("means this session cannot go direct", POL + "spec R1.6 and 'Transport exclusivity': every answer that is not worth another try means this SESSION cannot go direct"),
    ("busy", POL + "spec R2.6: a busy commit waits what the server states (rate_limit.rs:2028-2041) or backs off for itself (jitter_port.py)"),
    ("unwell", POL + "spec R4: an unwell grant is asked for again after a jittered wait (jitter_port.py); a stated wait is kept"),
    ("Held answer on a grant", POL + "a hold is a commit answer: " + RS + "routes/direct_transfer.rs:975, 1075, 1093, 1123 are all in commit_locked"),
]


def policy_source(name):
    for word, src in POLICY_SOURCES:
        if word in name:
            return src
    raise SystemExit(f"no source for the policy scenario {name!r}")


def scen(name, steps, seed=0):
    policy.append({"name": name, "seed": seed, "steps": steps, "source": policy_source(name)})


# A client-side wait carries equal jitter: a PUT that fails, a grant or commit that "may pass".
sim = Sim(11)
w1, w2, w3 = sim.failure(), sim.failure(), sim.failure()
scen("a PUT that fails is regranted with a doubling wait (equal jitter), and the fourth link is the last", [
    may(True), issued, fail("put", 403, retry(w1, GR)),
    may(True), issued, fail("put", 500, retry(w2, GR)),
    may(True), issued, fail("put", 0, retry(w3, GR)),
    may(True), issued, may(False), fail("put", 403, USE_API),
], seed=11)
# Review E2 (clients plan A1): a PUT that storage refused (403) and a PUT that got no answer (status 0) are decided alike.
for what, status in (("403", 403), ("status 0, no answer", 0)):
    sim = Sim(11)
    ws = [sim.failure() for _ in range(3)]
    scen(f"a PUT that storage refused ({what}) is decided like any failed PUT: the same jittered waits (equal jitter) and the fourth link is the last", [
        may(True), issued, fail("put", status, retry(ws[0], GR)),
        may(True), issued, fail("put", status, retry(ws[1], GR)),
        may(True), issued, fail("put", status, retry(ws[2], GR)),
        may(True), issued, may(False), fail("put", status, USE_API),
    ], seed=11)
sim = Sim(5)
sim.stated()
second = sim.failure()
scen("a commit that is busy waits the stated time exactly, a plain failure waits a jittered 2 s at most, and none of it is tied to the grants", [
    may(True), issued,
    fail("commit", BACKOFF(5000), retry(5000, CO)),
    fail("commit", RETRY, retry(second, CO)),
    fail("commit", BACKOFF(3000), retry(3000, CO)),
    may(True),
], seed=5)
scen("a chunk that was not stored is granted again at once", [
    may(True), issued, fail("commit", {"kind": "regrant"}, retry(0, GR)),
    issued, issued, issued, may(False), fail("commit", {"kind": "regrant"}, USE_API),
])
scen("a grant that is rate limited waits what the server says, within the budget", [
    fail("grant", BACKOFF(60000), retry(60000, GR)),
    fail("grant", BACKOFF(60000), retry(60000, GR)),
    fail("grant", BACKOFF(60000), USE_API),
])
scen("the budget is spent up to and including its last millisecond", [
    fail("commit", BACKOFF(90000), retry(90000, CO)),
    fail("commit", BACKOFF(60000), retry(60000, CO)),
    fail("commit", BACKOFF(1), USE_API),
])
sim = Sim(3)
a1 = sim.failure()
sim.stated()
a3 = sim.failure()
scen("a grant that is unwell is asked for again after a jittered wait, a stated wait is kept as it is", [
    fail("grant", RETRY, retry(a1, GR)),
    fail("grant", BACKOFF(3000), retry(3000, GR)),
    fail("grant", RETRY, retry(a3, GR)),
], seed=3)
for kind in ("api_for_this_file", "use_api_now", "not_supported", "restart"):
    scen(f"a grant answer of '{kind}' means this session cannot go direct", [fail("grant", {"kind": kind}, USE_API)])
    scen(f"a commit answer of '{kind}' means this session cannot go direct", [fail("commit", {"kind": kind}, USE_API)])
scen("an authorization answer on a grant is terminal", [fail("grant", {"kind": "terminal", "status": 403, "error": "forbidden"}, T403)])
scen("an authorization answer on a commit is terminal", [fail("commit", {"kind": "terminal", "status": 403, "error": "forbidden"}, T403)])
scen("a session that is gone is terminal for the caller's recovery", [
    fail("grant", {"kind": "terminal", "status": 404, "error": "not found"}, {"kind": "terminal", "status": 404, "error": "not found"})])
scen("the eighth failure ends the tries, however short the waits (seven are ridden out)", [
    fail("commit", BACKOFF(0), retry(0, CO), repeat=7),
    fail("commit", BACKOFF(0), USE_API)])
sim = Sim(7)
waits = [sim.failure() for _ in range(7)]
scen("seven retries with doubling jittered waits (the default doubling alone never reaches the 150 s budget); the eighth failure ends the tries", [
    *[fail("commit", RETRY, retry(w, CO)) for w in waits],
    fail("commit", RETRY, USE_API)], seed=7)

# ── the commit lock (R2.3, R3.1): after a copy that failed, 409 commit_in_progress lasts up to the lock TTL ──
sim = Sim(21)
copy_failed = sim.failure()
scen("a copy that failed leaves the commit held for minutes: 410 s of holds are waited out on their own allowance, no fallback", [
    fail("commit", RETRY, retry(copy_failed, CO)),
    fail("commit", HELD(10000), retry(10000, CO), repeat=41),
], seed=21)
scen("400 s of holds leave the retry budget untouched: a 150 s stated wait still fits, one millisecond more does not", [
    fail("commit", HELD(10000), retry(10000, CO), repeat=40),
    fail("commit", BACKOFF(150000), retry(150000, CO)),
    fail("commit", BACKOFF(1), USE_API),
])
scen("400 s of holds leave the failure cap untouched: seven failures are still ridden out, the eighth ends it", [
    fail("commit", HELD(10000), retry(10000, CO), repeat=40),
    fail("commit", BACKOFF(0), retry(0, CO), repeat=7),
    fail("commit", BACKOFF(0), USE_API),
])
scen("the hold allowance is the lock TTL plus 30 s, used to the millisecond: the last poll is cut, the next hold goes to the API", [
    fail("commit", HELD(120000), retry(120000, CO), repeat=3),
    fail("commit", HELD(120000), retry(90000, CO)),
    fail("commit", HELD(1000), USE_API),
])
scen("a hold that is spent is spent for the chunk: a later plain failure does not give it back", [
    fail("commit", HELD(120000), retry(120000, CO), repeat=3),
    fail("commit", HELD(120000), retry(90000, CO)),
    fail("commit", RETRY, retry(Sim(0).failure(), CO)),
    fail("commit", HELD(1000), USE_API),
])
sim = Sim(9)
polls = [sim.hold_poll() for _ in range(5)]
scen("holds the server states no wait for are polled every 5 s doubling to 15 s, each with equal jitter, until the allowance is spent", [
    *[fail("commit", HELD(None), retry(w, CO)) for w in polls],
    {"op": "exhaust_holds", "outcome": HELD(None), "already_ms": sum(polls), "total_ms": 450000, "each_max_ms": 15000, "each_min_ms": 7500},
], seed=9)
scen("a hold that states 0 or 999 ms is polled once a second, never faster, until the allowance is spent", [
    fail("commit", HELD(0), retry(1000, CO)),
    fail("commit", HELD(999), retry(1000, CO)),
    {"op": "exhaust_holds", "outcome": HELD(0), "already_ms": 2000, "total_ms": 450000, "each_max_ms": 1000, "each_min_ms": 1000},
])
scen("a Held answer on a grant is nothing the server sends: that session goes to the API", [
    fail("grant", HELD(10000), USE_API),
])

out = {
    "_provenance": "Task 2173 vectors for beebeeb_core::direct_transfer::upload: the grant and commit answer parsers, the init "
                   "transport rule and the per-chunk retry policy. Hand-authored from the spec (R1.1, R1.6, R2.4, R2.6, R3.4) and "
                   "the merged server's real bodies (server main 30c8ed62, routes/direct_transfer.rs). Read by the core tests in "
                   "upload.rs ONLY (exact row counts); the WASM and UniFFI exports do not load it (they take the parsers and the "
                   "policy when web/mobile ship uploads). The 'classify' rows for the upload calls live in direct_transfer.json "
                   "and ARE run by core, the WASM seams and the UniFFI exports. Every row has a `source` (a server file:line at "
                   "30c8ed62, a spec rule, or 'client policy' / 'client-side case' / 'synthetic'). Regenerate with "
                   "test-vectors/tools/make_direct_upload_vectors.py; the jittered waits come from test-vectors/tools/jitter_port.py.",
    "version": 1,
    "api_bases": {"prod": API_PROD, "dev": API_DEV},
    "discoveries": discoveries,
    "grant_answers": grant_answers,
    "commit_answers": commit_answers,
    "constants": constants,
    "init_transport": init_transport,
    "policy": policy,
}
json.dump(out, open(sys.argv[1], "w", encoding="utf-8"), indent=2, ensure_ascii=False)
print("rows: grant", len(grant_answers), "commit", len(commit_answers), "init", len(init_transport), "policy scenarios", len(policy))
