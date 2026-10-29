"""Hand-authored contract vectors for beebeeb_core::direct_transfer (task 2173).

The expectations come from the spec (docs/specs/2026-10-23-direct-download-hosts.md, R1.6 /
R1.12 / R1.13 / R2.6 and the review of core #33), NOT from running the code. Every runner
(core, WASM seams, UniFFI) must reproduce them, so a binding cannot drift from core.
usage: python3 -I make_vectors.py <out.json>
"""
import json
import sys

T0 = 1_800_000_000_000  # 2027-01-15T08:00:00Z in Unix ms
EXP300 = "2027-01-15T08:05:00Z"  # T0 + 300 s

PROD = "https://api.beebeeb.test"
DEV = "http://127.0.0.1:3001"

discoveries = {
    "std": {
        "download": ["object-download-v1"],
        "upload": [],
        "storage_hosts": ["s3.storage.test", "eu.storage.test"],
        "storage_buckets": [
            {"host": "s3.storage.test", "bucket": "bb-01"},
            {"host": "s3.storage.test", "bucket": "bb-02"},
            {"host": "eu.storage.test", "bucket": "vault"},
        ],
        "max_window": 32,
        "url_ttl_seconds": 300,
    },
    "ports": {  # the server lists host:port authorities: still refused off loopback (R1.12)
        "download": ["object-download-v1"],
        "storage_hosts": ["minio.storage.test:9443", "evil.storage.test:8443"],
        "storage_buckets": [
            {"host": "minio.storage.test:9443", "bucket": "bb"},
            {"host": "evil.storage.test:8443", "bucket": "bb"},
        ],
    },
    "dev": {
        "download": ["object-download-v1"],
        "storage_hosts": ["127.0.0.1:9000", "localhost:9000"],
        "storage_buckets": [
            {"host": "127.0.0.1:9000", "bucket": "bb-dev"},
            {"host": "localhost:9000", "bucket": "bb-dev"},
        ],
    },
    "hosts_only": {"download": ["object-download-v1"], "storage_hosts": ["s3.storage.test"]},
    # Listed buckets, but neither capability token: only the token rule can refuse it.
    "no_tokens": {
        "storage_hosts": ["s3.storage.test"],
        "storage_buckets": [{"host": "s3.storage.test", "bucket": "bb-01"}],
    },
    "empty": {},
    # Small windows so a 3-chunk file needs two of them.
    "small_window": {
        "download": ["object-download-v1"],
        "storage_hosts": ["s3.storage.test"],
        "storage_buckets": [{"host": "s3.storage.test", "bucket": "bb-01"}],
        "max_window": 2,
        "url_ttl_seconds": 300,
    },
}

K = "?X-Amz-Signature=SIG"
authority = []


def a(name, url, expect, api="prod", disc="std"):
    authority.append({"name": name, "url": url, "api_base": PROD if api == "prod" else DEV, "discovery": disc, "expect": expect})


S3 = "https://s3.storage.test"
a("plain presigned GET", f"{S3}/bb-01/tenant/versions/v/0.bin{K}&X-Amz-Expires=300", "ok")
a("second bucket, same host", f"{S3}/bb-02/k{K}", "ok")
a("another listed host", "https://eu.storage.test/vault/a/b/c", "ok")
a("upper-case scheme and host", "HTTPS://S3.Storage.TEST/bb-01/k?x=1", "ok")
a("explicit default port is the same authority", f"{S3}:443/bb-01/k", "ok")
a("bucket-looking key part", f"{S3}/bb-01/bb-02/k", "ok")
a("http to a public host", "http://s3.storage.test/bb-01/k", "not_https")
a("ftp", "ftp://s3.storage.test/bb-01/k", "not_https")
a("scheme-relative", "//s3.storage.test/bb-01/k", "not_https")
a("one slash (WHATWG repairs it)", "https:/s3.storage.test/bb-01/k", "not_https")
a("empty", "", "malformed")
a("userinfo", "https://user:secret@s3.storage.test/bb-01/k", "userinfo")
a("listed host as userinfo of another host", "https://s3.storage.test@evil.test/bb-01/k", "userinfo")
a("backslash host confusion", "https://evil.test\\@s3.storage.test/bb-01/k", "malformed")
a("fragment hides the real host", "https://evil.test#@s3.storage.test/bb-01/k", "malformed")
a("tab inside the host", "https://s3.stor\tage.test/bb-01/k", "malformed")
a("newline splits the host", "https://s3.storage.test\n.evil.test/bb-01/k", "malformed")
a("leading space", " https://s3.storage.test/bb-01/k", "malformed")
a("non-ASCII full stop", "https://s3。storage.test/bb-01/k", "malformed")
a("percent in the host", "https://s3%2estorage.test/bb-01/k", "bad_host")
a("unlisted host", "https://evil.test/bb-01/k", "host_not_listed")
a("listed host as a prefix of another", "https://s3.storage.test.evil.test/bb-01/k", "host_not_listed")
a("subdomain of a listed host", "https://x.s3.storage.test/bb-01/k", "host_not_listed")
a("virtual-hosted bucket form", "https://bb-01.s3.storage.test/k", "host_not_listed")
a("trailing dot", "https://s3.storage.test./bb-01/k", "bad_host")
a("empty port", "https://s3.storage.test:/bb-01/k", "bad_host")
a("port 0", "https://s3.storage.test:0/bb-01/k", "bad_host")
a("ipv4", "https://203.0.113.9/bb-01/k", "ip_literal")
a("ipv6", "https://[2001:db8::1]/bb-01/k", "ip_literal")
a("decimal ipv4", "https://2130706433/bb-01/k", "ip_literal")
a("hex ipv4", "https://0x7f000001/bb-01/k", "ip_literal")
a("short ipv4", "https://127.1/bb-01/k", "ip_literal")
a("loopback address on a production api", "https://127.0.0.1/bb-01/k", "loopback")
a("localhost on a production api", "https://localhost/bb-01/k", "loopback")
a("LOCALHOST on a production api", "https://LOCALHOST/bb-01/k", "loopback")
a("http localhost on a production api", "http://localhost:9000/bb-01/k", "not_https")
a("non-default port on a listed host", f"{S3}:8443/bb-01/k", "port")
a("non-default port on an unlisted host", "https://evil.test:8443/bb-01/k", "port")
a("unlisted bucket", f"{S3}/other/k", "bucket_not_listed")
a("bucket of another host", "https://eu.storage.test/bb-01/k", "bucket_not_listed")
a("bucket case differs", f"{S3}/BB-01/k", "bucket_not_listed")
a("no path", "https://s3.storage.test", "bucket_not_listed")
a("bucket only", f"{S3}/bb-01", "bucket_not_listed")
a("bucket with an empty key", f"{S3}/bb-01/", "bad_path")
a("dot-dot escapes to another bucket", f"{S3}/bb-01/../other/k", "bad_path")
a("encoded dot-dot", f"{S3}/bb-01/%2e%2e/other/k", "bad_path")
a("single dot segment", f"{S3}/bb-01/./k", "bad_path")
a("empty segment", f"{S3}/bb-01//k", "bad_path")
a("a listed non-default port is refused (R1.12)", "https://minio.storage.test:9443/bb/k", "port", disc="ports")
a("a hostile listed port is refused (R1.12)", "https://evil.storage.test:8443/bb/k", "port", disc="ports")
a("hosts listed but no buckets: fail closed", f"{S3}/bb-01/k", "bucket_not_listed", disc="hosts_only")
a("nothing listed, nothing allowed", f"{S3}/bb-01/k", "host_not_listed", disc="empty")
a("dev: http to loopback MinIO", "http://127.0.0.1:9000/bb-dev/k?x=1", "ok", api="dev", disc="dev")
a("dev: http to localhost MinIO", "http://localhost:9000/bb-dev/k", "ok", api="dev", disc="dev")
a("dev: https to loopback MinIO", "https://127.0.0.1:9000/bb-dev/k", "ok", api="dev", disc="dev")
a("dev: http to a public host", "http://s3.storage.test/bb-01/k", "not_https", api="dev")
a("dev: an unlisted loopback port", "http://127.0.0.1:9001/bb-dev/k", "host_not_listed", api="dev", disc="dev")
a("dev: another private address", "https://10.0.0.5:9000/bb-dev/k", "ip_literal", api="dev", disc="dev")
a("production api: the same loopback URL", "http://127.0.0.1:9000/bb-dev/k", "not_https", api="prod", disc="dev")

# ───────────────────────── classify ─────────────────────────
JSONCT = "application/json"
classify = []


def c(name, call, status, ct, body, retry, expect, src=None):
    row = {"name": name, "call": call, "status": status, "content_type": ct, "body": body, "retry_after": retry, "expect": expect}
    if src:
        row["source"] = src
    classify.append(row)


NF = '{"error":"not found"}'
c("discovery 200", "discovery", 200, JSONCT, "{}", None, {"kind": "proceed"})
c("discovery JSON 404 is not-supported", "discovery", 404, JSONCT, NF, None, {"kind": "not_supported"})
c("discovery bare 404 (an old server's unknown route)", "discovery", 404, None, "", None, {"kind": "use_api_now"})
c("discovery HTML 404", "discovery", 404, "text/html; charset=utf-8", "<h1>Not Found</h1>", None, {"kind": "use_api_now"})
c("discovery 405 (the old server's /transfer/{id} collision)", "discovery", 405, None, "", None, {"kind": "use_api_now"})
c("discovery 500", "discovery", 500, JSONCT, '{"error":"Something went wrong."}', None, {"kind": "use_api_now"})
c("discovery HTML 502", "discovery", 502, "text/html", "<html>Bad Gateway</html>", None, {"kind": "use_api_now"})
c("discovery no answer", "discovery", 0, None, "", None, {"kind": "use_api_now"})
c("discovery 429 does not make the command wait", "discovery", 429, JSONCT, '{"error":"rate_limited"}', "30", {"kind": "use_api_now"})
c("discovery 401", "discovery", 401, JSONCT, '{"error":"unauthorized"}', None, {"kind": "terminal", "status": 401, "error": "unauthorized"})
c("grant 200", "download_grant", 200, JSONCT, "{}", None, {"kind": "proceed"})
c("grant 401", "download_grant", 401, JSONCT, '{"error":"unauthorized"}', None, {"kind": "terminal", "status": 401, "error": "unauthorized"})
c("grant 403", "download_grant", 403, JSONCT, '{"error":"forbidden"}', None, {"kind": "terminal", "status": 403, "error": "forbidden"})
c("grant JSON 404 is a real not-found", "download_grant", 404, JSONCT, NF, None, {"kind": "terminal", "status": 404, "error": "not found"})
c("grant bare 404: this node has no route", "download_grant", 404, None, "", None, {"kind": "use_api_now"})
c("grant HTML 404", "download_grant", 404, "text/html", "<h1>Not Found</h1>", None, {"kind": "use_api_now"})
c("grant JSON-looking body under the wrong content type", "download_grant", 404, "text/plain", NF, None, {"kind": "use_api_now"})
c("grant 405", "download_grant", 405, None, "", None, {"kind": "use_api_now"})
c("409 direct_unavailable", "download_grant", 409, JSONCT, '{"error":"direct_unavailable","reason":"disabled"}', None, {"kind": "api_for_this_file"})
c("409 version_unavailable", "download_grant", 409, JSONCT, '{"error":"version_unavailable"}', None, {"kind": "restart"})
c("409 replace_in_progress: wait (R1.13)", "download_grant", 409, JSONCT, '{"error":"replace_in_progress"}', None, {"kind": "backoff", "millis": 5000})
c("409 replace_in_progress with Retry-After", "download_grant", 409, JSONCT, '{"error":"replace_in_progress"}', "3", {"kind": "backoff", "millis": 3000})
c("409 commit_in_progress: wait (R2.6)", "download_grant", 409, JSONCT, '{"error":"commit_in_progress"}', None, {"kind": "backoff", "millis": 5000})
c("409 unknown code", "download_grant", 409, JSONCT, '{"error":"something_new"}', None, {"kind": "api_for_this_file"})
c("409 with no JSON body", "download_grant", 409, None, "", None, {"kind": "api_for_this_file"})
c("429 with Retry-After", "download_grant", 429, JSONCT, '{"error":"rate_limited"}', "17", {"kind": "backoff", "millis": 17000})
c("429 without Retry-After", "download_grant", 429, JSONCT, '{"error":"rate_limited"}', None, {"kind": "backoff", "millis": 5000})
c("429 with an HTTP-date Retry-After", "download_grant", 429, JSONCT, "{}", "Wed, 21 Oct 2026 07:28:00 GMT", {"kind": "backoff", "millis": 5000})
c("429 with Retry-After 0 waits a second", "download_grant", 429, JSONCT, "{}", "0", {"kind": "backoff", "millis": 1000})
c("429 with a huge Retry-After is capped", "download_grant", 429, JSONCT, "{}", "86400", {"kind": "backoff", "millis": 120000})
c("grant 500", "download_grant", 500, JSONCT, '{"error":"Something went wrong."}', None, {"kind": "use_api_now"})
c("grant no answer", "download_grant", 0, None, "", None, {"kind": "use_api_now"})
c("grant 302 (redirects are never followed)", "download_grant", 302, None, "", None, {"kind": "use_api_now"})
c("grant 400 bad window", "download_grant", 400, JSONCT, '{"error":"count must be between 1 and 32"}', None, {"kind": "api_for_this_file"})

# The pinned per-chunk route (GET /files/{id}/chunks/{i}?object_version_id=<pin>). The server's body for a
# gone version is a SENTENCE (repos/server routes/version_download.rs `unavailable`), not the grant route's code.
GONE = '{"error":"download version unavailable; restart download from fresh metadata"}'
c("pinned 200", "pinned_chunk", 200, "application/octet-stream", "", None, {"kind": "proceed"})
c("pinned 409 with the server's real body: the pin is gone", "pinned_chunk", 409, JSONCT, GONE, None, {"kind": "restart"})
c("pinned bare 409: the pin is gone", "pinned_chunk", 409, None, "", None, {"kind": "restart"})
c("pinned 409 with the grant route's code: the pin is gone", "pinned_chunk", 409, JSONCT, '{"error":"version_unavailable"}', None, {"kind": "restart"})
c("pinned 409 with any other text: the pin is gone", "pinned_chunk", 409, JSONCT, '{"error":"something the server may say tomorrow"}', None, {"kind": "restart"})
c("pinned 409 replace_in_progress is a wait", "pinned_chunk", 409, JSONCT, '{"error":"replace_in_progress"}', None, {"kind": "backoff", "millis": 5000})
c("pinned 409 replace_in_progress with Retry-After", "pinned_chunk", 409, JSONCT, '{"error":"replace_in_progress"}', "3", {"kind": "backoff", "millis": 3000})
c("pinned 409 commit_in_progress is a wait", "pinned_chunk", 409, JSONCT, '{"error":"commit_in_progress"}', None, {"kind": "backoff", "millis": 5000})
# The server's real 429 on /api/v1/files/* (rate_limit.rs `too_many_requests`): this body and `Retry-After: 60`.
RATE_LIMITED = '{"error":"rate_limited","message":"Too many requests. Try again in 60 seconds.","retry_after":60}'
c("pinned 429, the server's real limiter body and Retry-After: 60", "pinned_chunk", 429, JSONCT, RATE_LIMITED, "60", {"kind": "backoff", "millis": 60000})
c("pinned 429 with a shorter Retry-After", "pinned_chunk", 429, JSONCT, RATE_LIMITED, "7", {"kind": "backoff", "millis": 7000})
c("pinned 429 without Retry-After", "pinned_chunk", 429, JSONCT, RATE_LIMITED, None, {"kind": "backoff", "millis": 5000})
c("pinned 429 with a huge Retry-After is capped", "pinned_chunk", 429, JSONCT, "{}", "86400", {"kind": "backoff", "millis": 120000})
c("pinned 500 may pass", "pinned_chunk", 500, JSONCT, '{"error":"Something went wrong."}', None, {"kind": "retry"})
c("pinned HTML 502 may pass", "pinned_chunk", 502, "text/html", "<html>Bad Gateway</html>", None, {"kind": "retry"})
c("pinned 503 may pass", "pinned_chunk", 503, None, "", None, {"kind": "retry"})
c("pinned 503 with the server's Retry-After: 5 is a stated wait", "pinned_chunk", 503, JSONCT, '{"error":"statement_timeout"}', "5", {"kind": "backoff", "millis": 5000})
c("pinned 500 with Retry-After 0 waits a second", "pinned_chunk", 500, None, "", "0", {"kind": "backoff", "millis": 1000})
c("pinned 502 with a huge Retry-After is capped", "pinned_chunk", 502, None, "", "86400", {"kind": "backoff", "millis": 120000})
c("pinned 503 with an unreadable Retry-After names nothing", "pinned_chunk", 503, None, "", "soon", {"kind": "retry"})
c("pinned no answer may pass", "pinned_chunk", 0, None, "", None, {"kind": "retry"})
c("pinned 302 may pass", "pinned_chunk", 302, None, "", None, {"kind": "retry"})
c("pinned bare 404: a node without the route may pass", "pinned_chunk", 404, None, "", None, {"kind": "retry"})
c("pinned 405 may pass", "pinned_chunk", 405, None, "", None, {"kind": "retry"})
c("pinned JSON 404 is a real not-found", "pinned_chunk", 404, JSONCT, NF, None, {"kind": "terminal", "status": 404, "error": "not found"})
c("pinned 401", "pinned_chunk", 401, JSONCT, '{"error":"unauthorized"}', None, {"kind": "terminal", "status": 401, "error": "unauthorized"})
c("pinned 403", "pinned_chunk", 403, JSONCT, '{"error":"forbidden"}', None, {"kind": "terminal", "status": 403, "error": "forbidden"})
c("pinned 400: an index out of range will not change", "pinned_chunk", 400, JSONCT, '{"error":"chunk index 9 out of range (version has 3 chunk(s))"}', None, {"kind": "api_for_this_file"})
c("pinned 410", "pinned_chunk", 410, None, "", None, {"kind": "api_for_this_file"})
c("pinned 413", "pinned_chunk", 413, None, "", None, {"kind": "api_for_this_file"})

# ── upload grant and commit ──
# `source` says where each row's body comes from. A row whose source starts "server 30c8ed62" is the server's own status and
# body ON THAT CALL (beebeeb-api at server main 30c8ed62; tests/direct_upload_2173.rs is the #331 test file and asserts
# the same bytes where it is named). Every other row says what it is: "synthetic" (a proxy, a front page, a framework
# fallback, a broken server) or "client-side case" (a server answer that exists, but not on this call or not with this
# header today, kept so the client's rule for it is pinned).
RS = "server 30c8ed62 beebeeb-api/src/"
GRANT_OK = '{"transport":"object-upload-v1","index":3,"method":"PUT","url":"https://s3.storage.test/bb-01/tenants/t/files/f/versions/v/staging/3/g.bin?X-Amz-Signature=SIG","headers":{"content-type":"application/octet-stream"},"expires_at":"2027-01-15T08:05:00Z"}'
COMMIT_OK = '{"index":3,"size":4194332,"skipped":false,"object_key":"tenants/t/files/f/versions/v/3.bin"}'
DIRECT_UNAVAILABLE = '{"error":"direct_unavailable","reason":"disabled"}'
QUOTA = '{"error":"quota_exceeded","limit_bytes":5368709120,"used_bytes":5368709000,"is_trial_cap":false}'
SIZE400 = '{"error":"size must be 4194332 bytes for chunk 3"}'
EXPIRED400 = '{"error":"upload session is not writable: expired"}'
STORAGE503 = '{"error":"File could not be saved. Our storage is having trouble \u2014 please try again."}'
TIMEOUT503 = '{"error":"statement_timeout","message":"This took too long, so the server stopped it. Try again in a moment."}'
CAP429 = '{"error":"rate_limited","message":"Too many requests. Try again in 587 seconds.","retry_after":587}'
CIP = '{"error":"commit_in_progress"}'
CNS = '{"error":"chunk_not_stored"}'
LIM = "rate_limit.rs:2028-2041 (too_many_requests: the body, Retry-After and X-RateLimit-*)"
CIP_SITES = "routes/direct_transfer.rs:912-914 (commit_in_progress), returned by commit_locked at 975, 1075, 1093, 1123"
SHARED = {  # answers both routes send through the same code
    "401": RS + "error.rs:1012 (ApiError::Unauthorized)",
    "403": RS + "error.rs:1013 (ApiError::Forbidden)",
    "404": RS + "error.rs:1008 (ApiError::NotFound: the session is not the caller's or is gone, load_upload_session); tests/direct_upload_2173.rs:360",
    "du": RS + "routes/direct_transfer.rs:55-65 (direct_unavailable; the commit route returns it at 942, 977, 1027, the grant route at 710-746); tests/direct_upload_2173.rs:982-1016 (the reasons)",
    "tm": RS + "routes/direct_transfer.rs:598-599 (direct_session) + error.rs:1014 (ApiError::Conflict); tests/direct_upload_2173.rs:344",
    "400size": RS + "routes/direct_transfer.rs:626-629 (direct_session: size) + error.rs:1010 (ApiError::BadRequest)",
    "400expired": RS + "routes/direct_transfer.rs:604-607 (direct_session: status) + error.rs:1010; the caller's session recovery reads this text before the classifier (CLI is_upload_session_gone)",
    "413": RS + "routes/direct_transfer.rs:674 (admit_chunk: ChunkBound::Quota, called by both routes) + error.rs:603-632 (ApiError::QuotaExceeded)",
    "500": RS + "error.rs:1025-1044 (ApiError::Internal: 'Something went wrong.')",
    "503r": RS + "error.rs:970-984 (a statement_timeout: 503 with Retry-After: 5)",
}
SYN = {
    "bare404": "no handler sends it: axum's unknown-route fallback (spec R1.6), a node without the route",
    "html404": "no handler sends it: a front proxy's page (spec R1.6)",
    "405": "no handler sends it: axum's method-not-allowed fallback, empty body (spec R1.6)",
    "other409": "synthetic: a code no handler sends today (spec R1.6: an unknown 409 is the API's to judge)",
    "bare409": "synthetic: a 409 with no body (a proxy); spec R1.6",
    "502": "no handler sends it: an edge proxy's page",
    "none": "no API answer: a network failure or timeout",
    "302": "no handler sends it: a proxy redirect (a wrong path, not a passing fault: this session cannot go direct)",
    "100": "no handler sends it: an interim response nothing asked for",
}
for call in ("upload_grant", "upload_commit"):
    w = "upload grant" if call == "upload_grant" else "upload commit"
    grant = call == "upload_grant"
    c(f"{w} 200", call, 200, JSONCT, GRANT_OK if grant else COMMIT_OK, None, {"kind": "proceed"},
      RS + ("routes/direct_transfer.rs:895-902 (upload_grant); tests/direct_upload_2173.rs:402-403" if grant else "routes/direct_transfer.rs:1137 (commit_locked); tests/direct_upload_2173.rs:472"))
    c(f"{w} 401", call, 401, JSONCT, '{"error":"unauthorized"}', None, {"kind": "terminal", "status": 401, "error": "unauthorized"}, SHARED["401"])
    c(f"{w} 403", call, 403, JSONCT, '{"error":"forbidden"}', None, {"kind": "terminal", "status": 403, "error": "forbidden"}, SHARED["403"])
    c(f"{w} JSON 404: the session is gone", call, 404, JSONCT, NF, None, {"kind": "terminal", "status": 404, "error": "not found"}, SHARED["404"])
    c(f"{w} bare 404: a node without the route", call, 404, None, "", None, {"kind": "api_for_this_file"}, SYN["bare404"])
    c(f"{w} HTML 404", call, 404, "text/html; charset=utf-8", "<h1>Not Found</h1>", None, {"kind": "api_for_this_file"}, SYN["html404"])
    c(f"{w} 405", call, 405, None, "", None, {"kind": "api_for_this_file"}, SYN["405"])
    c(f"{w} 409 direct_unavailable: this session cannot go direct", call, 409, JSONCT, DIRECT_UNAVAILABLE, None, {"kind": "api_for_this_file"}, SHARED["du"])
    c(f"{w} 409 transport_mismatch", call, 409, JSONCT, '{"error":"transport_mismatch"}', None, {"kind": "api_for_this_file"}, SHARED["tm"])
    c(f"{w} 409 with any other code", call, 409, JSONCT, '{"error":"something the server may say tomorrow"}', None, {"kind": "api_for_this_file"}, SYN["other409"])
    c(f"{w} bare 409", call, 409, None, "", None, {"kind": "api_for_this_file"}, SYN["bare409"])
    if grant:
        c(f"{w} 409 commit_in_progress: if one ever comes, a counted wait", call, 409, JSONCT, CIP, None, {"kind": "backoff", "millis": 5000},
          "client-side case: the grant route never sends commit_in_progress (only the commit route does: " + CIP_SITES + "); the client treats it as a short counted wait")
        c(f"{w} 409 commit_in_progress keeps a stated wait", call, 409, JSONCT, CIP, "3", {"kind": "backoff", "millis": 3000},
          "client-side case: the grant route never sends commit_in_progress, and no route sends Retry-After on it today")
    else:
        c(f"{w} 409 commit_in_progress: the lock is held, wait on its own allowance", call, 409, JSONCT, CIP, None, {"kind": "held", "millis": None},
          RS + CIP_SITES + "; tests/direct_upload_2173.rs:1427")
        c(f"{w} 409 commit_in_progress with the lock already released: the record's HEAD could not tell (R3.4), server 30c8ed62", call, 409, JSONCT, CIP, None, {"kind": "held", "millis": None},
          RS + "routes/direct_transfer.rs:1121-1123 (RecordOutcome::Unavailable -> commit_in_progress while the lock is no longer held); the allowance is also the bound on this case, where every poll re-copies the chunk")
        R34 = "client-side case: server PR after #338 (s3-server's local commit e05d316c, not pushed yet; its lines to be cited once it lands): "
        c(f"{w} 503 storage_unavailable with Retry-After: the R3.4 transients (the staging HEAD error, the record HEAD unavailable)", call, 503, JSONCT, '{"error":"storage_unavailable"}', "5", {"kind": "backoff", "millis": 5000},
          R34 + "storage_unavailable() answers every R3.4 transient with 503 {\"error\":\"storage_unavailable\"} and Retry-After: 5, a stated and COUNTED wait; 30c8ed62 answers the record case with commit_in_progress (the row above)")
        c(f"{w} 409 commit_in_progress with Retry-After = the lock's remaining TTL (287 s): a stated wait, clamped to 120 s", call, 409, JSONCT, CIP, "287", {"kind": "held", "millis": 120000},
          R34 + "the lock paths (acquire busy, confirm lost) answer commit_in_progress with Retry-After = the lock's remaining TTL in [1, commit_lock_secs() = 420], 1 when the key is gone; the client clamps a stated wait to 120 s and polls again")
        c(f"{w} 409 commit_in_progress with Retry-After = the lock's remaining TTL (30 s)", call, 409, JSONCT, CIP, "30", {"kind": "held", "millis": 30000}, R34 + "as above")
        c(f"{w} 409 commit_in_progress with Retry-After 1: the lock key is gone", call, 409, JSONCT, CIP, "1", {"kind": "held", "millis": 1000}, R34 + "as above (1 when the key is gone)")
        c(f"{w} 409 commit_in_progress keeps a stated wait", call, 409, JSONCT, CIP, "3", {"kind": "held", "millis": 3000},
          "client-side case: the server sends no Retry-After on commit_in_progress today (routes/direct_transfer.rs:912-914); a stated wait is kept")
        c(f"{w} 409 commit_in_progress states an hour: clamped", call, 409, JSONCT, CIP, "3600", {"kind": "held", "millis": 120000},
          "client-side case: the clamp (MAX_RETRY_AFTER) on a stated wait")
    if grant:
        c(f"{w} 429 with the real limiter body", call, 429, JSONCT, RATE_LIMITED, "60", {"kind": "backoff", "millis": 60000},
          RS + LIM + "; the grant budget at routes/direct_transfer.rs:814-816; tests/direct_upload_2173.rs:1011")
        c(f"{w} 429 the fifth grant of a chunk states the link's remaining life, more than a client will wait", call, 429, JSONCT, CAP429, "587", {"kind": "backoff", "millis": 120000},
          RS + LIM + "; routes/direct_transfer.rs:770-775 (TooManyGrants -> rate_limited_response(retry_after, 4)); direct_transfer.rs:790-792 (retry_after = the grants key's remaining life, link lifetime + PUT allowance, about 600 s for a fresh chunk; 587 is an example); tests/direct_upload_2173.rs:1475-1477")
    else:
        c(f"{w} 429 with the real limiter body", call, 429, JSONCT, RATE_LIMITED, "60", {"kind": "backoff", "millis": 60000},
          RS + "router.rs:584-587 (rate_limit_by_user over the upload routes: the only 429 the commit route sends) + " + LIM + " (the 60 is a window length, an example)")
        c(f"{w} 429 states more than a client will wait", call, 429, JSONCT, '{"error":"rate_limited","message":"Too many requests. Try again in 300 seconds.","retry_after":300}', "300", {"kind": "backoff", "millis": 120000},
          "client-side case: no commit answer states this long today; the clamp (MAX_RETRY_AFTER) is the client's")
    c(f"{w} 400: a size the geometry does not allow", call, 400, JSONCT, SIZE400, None, {"kind": "api_for_this_file"}, SHARED["400size"])
    c(f"{w} 400: the session is not writable", call, 400, JSONCT, EXPIRED400, None, {"kind": "api_for_this_file"}, SHARED["400expired"])
    c(f"{w} 413 quota", call, 413, JSONCT, QUOTA, None, {"kind": "api_for_this_file"}, SHARED["413"])
    c(f"{w} 500 may pass", call, 500, JSONCT, '{"error":"Something went wrong."}', None, {"kind": "retry"}, SHARED["500"])
    c(f"{w} 502 may pass", call, 502, "text/html", "<html>Bad Gateway</html>", None, {"kind": "retry"}, SYN["502"])
    if grant:
        c(f"{w} 503 from storage, no Retry-After", call, 503, JSONCT, STORAGE503, None, {"kind": "retry"},
          "client-side case: only the commit route sends the storage 503 (storage_failed, routes/direct_transfer.rs:1042, 1085); the rule is the same on both calls")
    else:
        c(f"{w} 503 from storage, no Retry-After", call, 503, JSONCT, STORAGE503, None, {"kind": "retry"},
          RS + "error.rs:1075 (ApiError::Storage -> 503, no Retry-After) + routes/direct_transfer.rs:916-925 (storage_failed), returned at 1042 (the commit's HEAD) and 1085 (its COPY)")
    c(f"{w} 503 states its wait", call, 503, JSONCT, TIMEOUT503, "5", {"kind": "backoff", "millis": 5000}, SHARED["503r"])
    c(f"{w} no answer may pass", call, 0, None, "", None, {"kind": "retry"}, SYN["none"])
    c(f"{w} 302 is a path that is wrong, not a passing fault", call, 302, None, "", None, {"kind": "api_for_this_file"}, SYN["302"])
    c(f"{w} 100 is no answer to what was asked", call, 100, None, "", None, {"kind": "api_for_this_file"}, SYN["100"])
c("upload commit 409 chunk_not_stored: nothing was committed, grant again", "upload_commit", 409, JSONCT, CNS, None, {"kind": "regrant"},
  RS + "routes/direct_transfer.rs:906-908 (chunk_not_stored), returned at 1025, 1045, 1121; tests/direct_upload_2173.rs:414")
c("upload grant 409 chunk_not_stored is not a grant answer", "upload_grant", 409, JSONCT, CNS, None, {"kind": "api_for_this_file"},
  "client-side case: only the commit route sends it (routes/direct_transfer.rs:1025, 1045, 1121)")

# The shared retry policy for that route (default: 4 attempts, 60 s of waiting in all, 1 s doubling).
pinned_retry = []


def r(name, outcome, attempt, waited_ms, expect):
    pinned_retry.append({"name": name, "outcome": outcome, "attempt": attempt, "waited_ms": waited_ms, "expect": expect})


RETRY = {"kind": "retry"}
GIVE_UP = {"kind": "give_up"}
r("first failure of a server hiccup waits 1 s", RETRY, 1, 0, {"kind": "wait", "millis": 1000})
r("second doubles", RETRY, 2, 1000, {"kind": "wait", "millis": 2000})
r("third doubles again", RETRY, 3, 3000, {"kind": "wait", "millis": 4000})
r("the fourth attempt was the last", RETRY, 4, 7000, GIVE_UP)
r("a stated wait is kept", {"kind": "backoff", "millis": 3000}, 1, 0, {"kind": "wait", "millis": 3000})
RATE_60 = {"kind": "backoff", "millis": 60000}
r("the server's real 429 (Retry-After: 60) at attempt 1, nothing waited", RATE_60, 1, 0, {"kind": "wait", "millis": 60000})
r("the same 429 at attempt 2 after a 1 s hiccup", RATE_60, 2, 1000, {"kind": "wait", "millis": 60000})
r("a second 429 right after the first", RATE_60, 2, 60000, {"kind": "wait", "millis": 60000})
r("a ban clamped to 120 s is waited for once", {"kind": "backoff", "millis": 120000}, 1, 0, {"kind": "wait", "millis": 120000})
r("a third 60 s wait (180 s in all) is past the budget", RATE_60, 3, 120000, GIVE_UP)
r("a stated wait ending exactly at the budget (150 s) is taken", RATE_60, 2, 90000, {"kind": "wait", "millis": 60000})
r("one millisecond past the budget is not", RATE_60, 2, 90001, GIVE_UP)
r("a ban after a long wait does not fit", {"kind": "backoff", "millis": 120000}, 2, 31000, GIVE_UP)
r("attempt 0 is read as the first attempt", RETRY, 0, 0, {"kind": "wait", "millis": 1000})
r("a stated wait on the last attempt is not taken", {"kind": "backoff", "millis": 1000}, 4, 0, GIVE_UP)
r("a gone pin is not retried", {"kind": "restart"}, 1, 0, GIVE_UP)
r("an authorization answer is not retried", {"kind": "terminal", "status": 403, "error": "forbidden"}, 1, 0, GIVE_UP)
r("a refusal a retry cannot change is not retried", {"kind": "api_for_this_file"}, 1, 0, GIVE_UP)
r("a success needs no retry", {"kind": "proceed"}, 1, 0, GIVE_UP)
r("the doubling cannot overflow", RETRY, 4000000000, 0, GIVE_UP)

# The discovery cache (10 minutes of trust; a good answer, a JSON 404 and two failed attempts all expire).
TTL = 600_000
cache = []


def lookup(now, expect):
    return {"op": "lookup", "now": now, "expect": expect}


def record(now, outcome, body=None):
    return {"op": "record", "now": now, "outcome": outcome, "body": body}


USE_API_NOW = {"kind": "use_api_now"}
cache.append({"name": "a good answer is reused for ten minutes, then asked for again", "steps": [
    lookup(T0, "fetch"), record(T0, {"kind": "proceed"}, "@std"), lookup(T0, "cached"),
    lookup(T0 + TTL - 1, "cached"), lookup(T0 + TTL, "fetch"), lookup(T0 - 1, "fetch")]})
cache.append({"name": "a JSON 404 is remembered for ten minutes, not for ever", "steps": [
    lookup(T0, "fetch"), record(T0, {"kind": "not_supported"}), lookup(T0 + 1, "use_api"),
    lookup(T0 + TTL - 1, "use_api"), lookup(T0 + TTL, "fetch"),
    record(T0 + TTL, {"kind": "not_supported"}), lookup(T0 + TTL + 1, "use_api"), lookup(T0 + 2 * TTL, "fetch")]})
cache.append({"name": "two failed attempts stop the asking for ten minutes, then it asks again", "steps": [
    lookup(T0, "fetch"), record(T0, USE_API_NOW), lookup(T0 + 1, "fetch"), record(T0 + 1, USE_API_NOW),
    lookup(T0 + 2, "use_api"), lookup(T0 + 1 + TTL - 1, "use_api"), lookup(T0 + 1 + TTL, "fetch"),
    lookup(T0, "fetch")]})
cache.append({"name": "the re-probe gets a fresh allowance of two", "steps": [
    record(T0, USE_API_NOW), record(T0 + 1, USE_API_NOW), lookup(T0 + 2, "use_api"),
    record(T0 + 1 + TTL, USE_API_NOW), lookup(T0 + 2 + TTL, "fetch"),
    record(T0 + 2 + TTL, USE_API_NOW), lookup(T0 + 3 + TTL, "use_api")]})
cache.append({"name": "failures further apart than ten minutes do not add up", "steps": [
    record(T0, USE_API_NOW), record(T0 + TTL + 5, USE_API_NOW), lookup(T0 + TTL + 6, "fetch")]})
cache.append({"name": "a success after a failure clears the count", "steps": [
    record(T0, USE_API_NOW), record(T0 + 1, {"kind": "proceed"}, "@std"), lookup(T0 + 2, "cached"),
    lookup(T0 + 1 + TTL, "fetch"),
    # the success cleared the old failure: one new failure is the first of two, not the second
    record(T0 + 2, USE_API_NOW), lookup(T0 + 1 + TTL, "fetch")]})
cache.append({"name": "a discovery body sent as text", "steps": [
    record(T0, {"kind": "proceed"}, json.dumps(discoveries["std"])), lookup(T0 + 1, "cached")]})
cache.append({"name": "a success whose body does not decode is a failed attempt", "steps": [
    record(T0, {"kind": "proceed"}, "not json"), record(T0 + 1, {"kind": "proceed"}), lookup(T0 + 2, "use_api")]})
AUTH_401 = {"kind": "terminal", "status": 401, "error": "unauthorized"}
AUTH_403 = {"kind": "terminal", "status": 403, "error": "forbidden"}
cache.append({"name": "repeated authorization answers are not routing failures", "steps": [
    record(T0, AUTH_401), lookup(T0 + 1, "fetch"),
    record(T0 + 1, AUTH_401), record(T0 + 2, AUTH_403), lookup(T0 + 3, "fetch")]})
cache.append({"name": "authorization preserves the real failure budget and its expiry", "steps": [
    record(T0, USE_API_NOW), record(T0 + 1, AUTH_403), lookup(T0 + 2, "fetch"),
    record(T0 + 3, USE_API_NOW), lookup(T0 + 4, "use_api"), record(T0 + 5, AUTH_403),
    lookup(T0 + 3 + TTL, "fetch")]})
cache.append({"name": "authorization does not prolong expired discovery", "steps": [
    record(T0, {"kind": "proceed"}, "@std"), record(T0 + TTL - 2, AUTH_401),
    record(T0 + TTL - 1, AUTH_401), lookup(T0 + TTL - 1, "cached"), lookup(T0 + TTL, "fetch")]})

redact = [
    {"input": f"{S3}/bb-01/tenant-0000/versions/v-1111/0.bin?X-Amz-Signature=abc&x=1", "expect": "https://s3.storage.test/<redacted>"},
    {"input": f"{S3}/bb-01/k#frag?x", "expect": "https://s3.storage.test/<redacted>"},
    {"input": "https://u:pw@s3.storage.test/b/k?q", "expect": "https://s3.storage.test/<redacted>"},
    {"input": "https://s3.storage.test", "expect": "https://s3.storage.test"},
    {"input": "https://s3.storage.test/", "expect": "https://s3.storage.test/"},
    {"input": "not a url?secret=1", "expect": "not a url"},
]
scrub = [
    {"input": "error sending request for url (https://s3.storage.test/bb-01/k?X-Amz-Signature=SECRETSIG&X-Amz-Credential=AKID): connection reset",
     "expect": "error sending request for url (https://s3.storage.test/<redacted>): connection reset"},
    {"input": "a http://h.test/p?s=1 b HTTPS://h2.test/q?t=2 c", "expect": "a http://h.test/<redacted> b HTTPS://h2.test/<redacted> c"},
    {"input": "retrying with X-Amz-Signature=SECRETSIG next", "expect": "retrying with x-amz-[redacted] next"},
    {"input": "nothing to hide", "expect": "nothing to hide"},
]

# chunk_length(geometry, index) -> length or null
geometry = [
    {"name": "full chunk", "chunk_count": 20, "chunk_size": 1000, "encrypted_size": 20060, "index": 0, "expect": 1028},
    {"name": "last chunk is the remainder", "chunk_count": 20, "chunk_size": 1000, "encrypted_size": 20060, "index": 19, "expect": 528},
    {"name": "one past the last chunk", "chunk_count": 20, "chunk_size": 1000, "encrypted_size": 20060, "index": 20, "expect": None},
    {"name": "index u32::MAX", "chunk_count": 20, "chunk_size": 1000, "encrypted_size": 20060, "index": 4294967295, "expect": None},
    {"name": "no chunks", "chunk_count": 0, "chunk_size": 10, "encrypted_size": 0, "index": 0, "expect": None},
    {"name": "the empty file is one empty chunk", "chunk_count": 1, "chunk_size": 1000, "encrypted_size": 28, "index": 0, "expect": 28},
    {"name": "stride overflow", "chunk_count": 2, "chunk_size": "18446744073709551610", "encrypted_size": 100, "index": 0, "expect": None},
    {"name": "stride times count overflows", "chunk_count": 4294967295, "chunk_size": "1099511627776", "encrypted_size": "18446744073709551615", "index": 4294967294, "expect": None},
]

# ───────────────────────── planner scenarios ─────────────────────────
FILE = "11111111-1111-4111-8111-111111111111"
VER = "22222222-2222-4222-8222-222222222222"
api_base = PROD


def grant(i, length, sig="SIG"):
    return {"index": i, "method": "GET", "url": f"{S3}/bb-01/t/v/{i}.bin?X-Amz-Signature={sig}{i}", "length": length, "expires_at": EXP300}


G = [1028, 1028, 528]  # 3 chunks: stride 1000, last 500 plaintext


def window(start, count, next_index):
    return {
        "transport": "object-download-v1", "file_id": FILE, "object_version_id": VER,
        "chunk_count": 3, "chunk_size": 1000, "encrypted_size": sum(G), "original_size": sum(G) - 84,
        "grants": [grant(i, G[i]) for i in range(start, start + count)], "next_index": next_index,
    }


def req(ver, start, count, renewal):
    return {"kind": "request_window", "request": {"object_version_id": ver, "start_index": start, "count": count, "renewal": renewal}}


def fetch(i):
    return {"kind": "fetch", "index": i, "url": f"{S3}/bb-01/t/v/{i}.bin?X-Amz-Signature=SIG{i}", "length": G[i]}


def poll(now, expect):
    return {"op": "poll", "now": now, "expect": expect}


def api(i):
    return {"kind": "fetch_via_api", "index": i, "object_version_id": VER}


WAIT_NONE = {"kind": "wait", "until_ms": None}
DONE = {"kind": "done"}

scenarios = []

def inspect(geometry, pinned, consumed, in_flight):
    return {"op": "inspect", "expect": {"geometry": geometry, "pinned_version": pinned, "consumed": consumed, "in_flight": in_flight}}


GEOMETRY = {"chunk_count": 3, "chunk_size": 1000, "encrypted_size": sum(G), "original_size": sum(G) - 84}

# 1. happy path, one window
steps = [poll(T0, req(None, 0, 8, False)), inspect(None, None, 0, 0),
         {"op": "window_answered", "now": T0, "response": window(0, 3, None), "expect": "ok"}, inspect(GEOMETRY, VER, 0, 0)]
steps += [poll(T0, fetch(0)), poll(T0, fetch(1)), poll(T0, fetch(2)), poll(T0, WAIT_NONE), inspect(GEOMETRY, VER, 0, 3)]
for i in range(3):
    steps += [{"op": "fetch_ok", "index": i, "expect": "ok"}, {"op": "consumed", "index": i, "expect": "ok"}]
    steps += [inspect(GEOMETRY, VER, i + 1, 2 - i)]
steps += [poll(T0, DONE)]
scenarios.append({"name": "one window, three chunks", "discovery": "std", "seed": 7, "steps": steps})

# 2. two windows (max_window 2): the refill is asked for while chunks 0 and 1 are still unused
steps = [poll(T0, req(None, 0, 2, False)), {"op": "window_answered", "now": T0, "response": window(0, 2, 2), "expect": "ok"},
         poll(T0, req(VER, 2, 1, False)), {"op": "window_answered", "now": T0, "response": window(2, 1, None), "expect": "ok"},
         poll(T0, fetch(0)), poll(T0, fetch(1)), poll(T0, fetch(2))]
for i in range(3):
    steps += [{"op": "fetch_ok", "index": i, "expect": "ok"}, {"op": "consumed", "index": i, "expect": "ok"}]
steps += [poll(T0, DONE)]
scenarios.append({"name": "two windows: the pin travels with the second", "discovery": "small_window", "seed": 7, "steps": steps})

# 3. a failed chunk is renewed after a backoff, then fetched again
steps = [poll(T0, req(None, 0, 8, False)), {"op": "window_answered", "now": T0, "response": window(0, 3, None), "expect": "ok"},
         poll(T0, fetch(0)), {"op": "fetch_failed", "index": 0, "now": T0 + 1000, "expect": "ok"},
         poll(T0 + 1000, fetch(1)), poll(T0 + 1000, fetch(2)),
         poll(T0 + 1000, {"kind": "wait", "until_ms_between": [T0 + 1125, T0 + 1250]}),
         poll(T0 + 1250, req(VER, 0, 1, True)),
         {"op": "window_answered", "now": T0 + 1250, "response": {**window(0, 1, 1), "grants": [grant(0, G[0], "NEWSIG")]}, "expect": "ok"},
         poll(T0 + 1250, {"kind": "fetch", "index": 0, "url": f"{S3}/bb-01/t/v/0.bin?X-Amz-Signature=NEWSIG0", "length": G[0]})]
scenarios.append({"name": "a failed chunk is renewed after a backoff", "discovery": "std", "seed": 7, "steps": steps})

# 4. the renewal budget: 3 renewals, the 4th failure goes to the pinned route
steps = [poll(T0, req(None, 0, 8, False)), {"op": "window_answered", "now": T0, "response": window(0, 3, None), "expect": "ok"},
         poll(T0, fetch(0)), poll(T0, fetch(1)), poll(T0, fetch(2))]
now = T0
for n in range(1, 4):
    steps += [{"op": "fetch_failed", "index": 0, "now": now, "expect": "ok"}]
    now += 10_000  # past any backoff (cap 8 s)
    steps += [poll(now, req(VER, 0, 1, True)),
              {"op": "window_answered", "now": now, "response": {**window(0, 1, 1), "grants": [grant(0, G[0], f"R{n}SIG")]}, "expect": "ok"},
              poll(now, {"kind": "fetch", "index": 0, "url": f"{S3}/bb-01/t/v/0.bin?X-Amz-Signature=R{n}SIG0", "length": G[0]})]
steps += [{"op": "fetch_failed", "index": 0, "now": now, "expect": "ok"}, poll(now, api(0))]
scenarios.append({"name": "three renewals, then the pinned API route", "discovery": "std", "seed": 7, "steps": steps})

# 5. a window the server cannot serve after the version is pinned (R1.6): the rest goes to the pinned route
steps = [poll(T0, req(None, 0, 2, False)), {"op": "window_answered", "now": T0, "response": window(0, 2, 2), "expect": "ok"},
         poll(T0, req(VER, 2, 1, False)), {"op": "window_failed", "now": T0, "outcome": {"kind": "api_for_this_file"}},
         poll(T0, fetch(0)), poll(T0, fetch(1)), poll(T0, api(2))]
for i in range(3):
    steps += [{"op": "fetch_ok", "index": i, "expect": "ok"}, {"op": "consumed", "index": i, "expect": "ok"}]
steps += [poll(T0, DONE)]
scenarios.append({"name": "a refused window after pinning moves the rest to the pinned route", "discovery": "small_window", "seed": 7, "steps": steps})

# 6. the same before pinning: nothing is written, the file goes to the API path
steps = [poll(T0, req(None, 0, 8, False)), {"op": "window_failed", "now": T0, "outcome": {"kind": "use_api_now"}},
         poll(T0, {"kind": "stop", "verdict": {"kind": "api_for_file"}})]
scenarios.append({"name": "a refused first window sends the file to the API path", "discovery": "std", "seed": 7, "steps": steps})

# 7. restart and terminal stay final
steps = [poll(T0, req(None, 0, 2, False)), {"op": "window_answered", "now": T0, "response": window(0, 2, 2), "expect": "ok"},
         poll(T0, req(VER, 2, 1, False)), {"op": "window_failed", "now": T0, "outcome": {"kind": "restart"}},
         poll(T0, {"kind": "stop", "verdict": {"kind": "restart"}})]
scenarios.append({"name": "version_unavailable restarts", "discovery": "small_window", "seed": 7, "steps": steps})
steps = [poll(T0, req(None, 0, 8, False)),
         {"op": "window_failed", "now": T0, "outcome": {"kind": "terminal", "status": 403, "error": "forbidden"}},
         poll(T0, {"kind": "stop", "verdict": {"kind": "terminal", "status": 403, "error": "forbidden"}})]
scenarios.append({"name": "a 403 is terminal", "discovery": "std", "seed": 7, "steps": steps})

# 8. authentication failure: one API re-fetch, then a hard error
steps = [poll(T0, req(None, 0, 8, False)), {"op": "window_answered", "now": T0, "response": window(0, 3, None), "expect": "ok"},
         poll(T0, fetch(0)), {"op": "fetch_ok", "index": 0, "expect": "ok"}, {"op": "chunk_unauthentic", "index": 0, "expect": "ok"},
         poll(T0, api(0)),
         {"op": "fetch_ok", "index": 0, "expect": "ok"}, {"op": "chunk_unauthentic", "index": 0, "expect": "ok"},
         poll(T0, {"kind": "stop", "verdict": {"kind": "corrupt"}})]
scenarios.append({"name": "an unauthentic chunk is fetched once more through the API, then is corrupt", "discovery": "std", "seed": 7, "steps": steps})

# 9. answers that break the contract
bad = []
for what, mutate, code in [
    ("wrong transport", lambda w: w.update(transport="object-download-v2"), "transport"),
    ("other file", lambda w: w.update(file_id="33333333-3333-4333-8333-333333333333"), "file_mismatch"),
    ("geometry not of any version", lambda w: w.update(encrypted_size=w["encrypted_size"] + 1), "geometry"),
    ("a grant too few", lambda w: w["grants"].pop(), "grants"),
    ("a PUT grant", lambda w: w["grants"][1].update(method="PUT"), "method"),
    ("a wrong chunk length", lambda w: w["grants"][1].update(length=w["grants"][1]["length"] + 1), "length"),
    ("an unlisted host", lambda w: w["grants"][0].update(url="https://evil.test/bb-01/k?s=1"), "authority_host_not_listed"),
    ("a plain-http link", lambda w: w["grants"][0].update(url="http://s3.storage.test/bb-01/k?s=1"), "authority_not_https"),
    # one answer per link refusal: the planner reports `authority_<refusal>` for each
    ("a link that does not parse", lambda w: w["grants"][0].update(url="https://evil.test\\@s3.storage.test/bb-01/k?s=1"), "authority_malformed"),
    ("a link with userinfo", lambda w: w["grants"][0].update(url="https://s3.storage.test@evil.test/bb-01/k?s=1"), "authority_userinfo"),
    ("an IP-literal link", lambda w: w["grants"][0].update(url="https://203.0.113.9/bb-01/k?s=1"), "authority_ip_literal"),
    ("a loopback link on a production api", lambda w: w["grants"][0].update(url="https://127.0.0.1/bb-01/k?s=1"), "authority_loopback"),
    ("a trailing-dot host", lambda w: w["grants"][0].update(url="https://s3.storage.test./bb-01/k?s=1"), "authority_bad_host"),
    ("a non-default port", lambda w: w["grants"][0].update(url="https://s3.storage.test:8443/bb-01/k?s=1"), "authority_port"),
    ("an unlisted bucket", lambda w: w["grants"][0].update(url="https://s3.storage.test/other/k?s=1"), "authority_bucket_not_listed"),
    ("a dot-dot path", lambda w: w["grants"][0].update(url="https://s3.storage.test/bb-01/../other/k?s=1"), "authority_bad_path"),
    ("an unreadable expiry", lambda w: w["grants"][0].update(expires_at="tomorrow"), "expiry"),
]:
    w = window(0, 3, None)
    mutate(w)
    bad.append({"name": what, "response": w, "expect": code})
bad += [
    {"name": "a body that is not JSON", "body": "{not json", "expect": "malformed"},
    {"name": "JSON that is not an object", "body": "[]", "expect": "malformed"},
    {"name": "an empty body", "body": "", "expect": "malformed"},
    {"name": "an object without the contract's fields", "body": "{}", "expect": "malformed"},
]
scenarios.append({"name": "answers that break the contract", "discovery": "std", "seed": 7, "refusals": bad})

# 10. a malformed answer
steps = [poll(T0, req(None, 0, 8, False)), {"op": "window_malformed"}, poll(T0, {"kind": "stop", "verdict": {"kind": "api_for_file"}})]
scenarios.append({"name": "an undecodable first window", "discovery": "std", "seed": 7, "steps": steps})

# 10b. the same through the raw body: the planner is told, and the file goes to the API path
steps = [poll(T0, req(None, 0, 8, False)), {"op": "window_answered", "now": T0, "body": "{not json", "expect": "malformed"},
         poll(T0, {"kind": "stop", "verdict": {"kind": "api_for_file"}})]
scenarios.append({"name": "an undecodable first window body", "discovery": "std", "seed": 7, "steps": steps})

# 10b2. a body given as text that IS the contract's JSON is accepted like the object form
steps = [poll(T0, req(None, 0, 8, False)),
         {"op": "window_answered", "now": T0, "body": json.dumps(window(0, 3, None)), "expect": "ok"},
         poll(T0, fetch(0))]
scenarios.append({"name": "a window body sent as text", "discovery": "std", "seed": 7, "steps": steps})

# 10c. a 429 on the window request: wait the stated time (R1.6/R1.13), then ask again
steps = [poll(T0, req(None, 0, 8, False)),
         {"op": "window_failed", "now": T0, "outcome": {"kind": "backoff", "millis": 2500}},
         poll(T0 + 1000, {"kind": "wait", "until_ms": T0 + 2500}),
         poll(T0 + 2500, req(None, 0, 8, False))]
scenarios.append({"name": "a 429 on the window request waits the stated time", "discovery": "std", "seed": 7, "steps": steps})

# 11. clock bands: expires_at is 20 s away (this clock runs 280 s ahead): the TTL counts from arrival
arrival = T0 + 280_000
steps = [poll(arrival, req(None, 0, 8, False)), {"op": "window_answered", "now": arrival, "response": window(0, 3, None), "expect": "ok"},
         poll(arrival + 269_999, fetch(0)),
         ]
scenarios.append({"name": "a clock 280 s ahead does not read the link as short", "discovery": "std", "seed": 7, "steps": steps})

# 12. a window nobody asked for ends the direct path for this file
steps = [{"op": "window_answered", "now": T0, "response": window(0, 3, None), "expect": "unexpected"},
         poll(T0, {"kind": "stop", "verdict": {"kind": "api_for_file"}})]
scenarios.append({"name": "an unsolicited window", "discovery": "std", "seed": 7, "steps": steps})

# 13. a later window for another version restarts the file
OTHER_VER = "44444444-4444-4444-8444-444444444444"
steps = [poll(T0, req(None, 0, 2, False)), {"op": "window_answered", "now": T0, "response": window(0, 2, 2), "expect": "ok"},
         poll(T0, req(VER, 2, 1, False)),
         {"op": "window_answered", "now": T0, "response": {**window(2, 1, None), "object_version_id": OTHER_VER}, "expect": "version_changed"},
         poll(T0, {"kind": "stop", "verdict": {"kind": "restart"}})]
scenarios.append({"name": "a window for another version restarts the file", "discovery": "small_window", "seed": 7, "steps": steps})

# 14. calls that do not fit the planner's state (a bug in the caller) are errors with a code
steps = [poll(T0, req(None, 0, 8, False)), {"op": "window_answered", "now": T0, "response": window(0, 3, None), "expect": "ok"},
         poll(T0, fetch(0)), poll(T0, fetch(1)),
         {"op": "fetch_ok", "index": 5, "expect": "not_in_flight"},
         {"op": "fetch_failed", "index": 5, "now": T0, "expect": "not_in_flight"},
         {"op": "consumed", "index": 0, "expect": "not_fetched"},
         {"op": "fetch_ok", "index": 1, "expect": "ok"},
         {"op": "consumed", "index": 1, "expect": "out_of_order"},
         {"op": "api_fetch_failed", "index": 0, "expect": "not_in_flight"},
         {"op": "chunk_unauthentic", "index": 2, "expect": "not_fetched"}]
scenarios.append({"name": "calls that do not fit the planner's state", "discovery": "std", "seed": 7, "steps": steps})

# 15. a failure on the pinned route is reported with api_fetch_failed, and ends the direct path
steps = list(scenarios[3]["steps"])  # "three renewals, then the pinned API route": chunk 0 is now on the pinned route
steps += [{"op": "fetch_failed", "index": 0, "now": now, "expect": "api_route_failure"},
          {"op": "api_fetch_failed", "index": 0, "expect": "ok"},
          poll(now, {"kind": "stop", "verdict": {"kind": "api_for_file"}})]
scenarios.append({"name": "a failure on the pinned route sends the file to the API path", "discovery": "std", "seed": 7, "steps": steps})

# 16. a window answer with no request outstanding is one caller-bug verdict, whatever the body is
# (before: junk read as "malformed" and a pinned file carried on through the pinned route)
for what, late in [("undecodable", "{not json"), ("empty", ""), ("valid", json.dumps(window(0, 3, None)))]:
    steps = [poll(T0, req(None, 0, 8, False)),
             {"op": "window_answered", "now": T0, "body": json.dumps(window(0, 3, None)), "expect": "ok"},
             {"op": "window_answered", "now": T0, "body": late, "expect": "unexpected"},
             poll(T0, {"kind": "stop", "verdict": {"kind": "api_for_file"}})]
    scenarios.append({"name": f"a late {what} window answer after the version is pinned", "discovery": "std", "seed": 7, "steps": steps})

# 17. a verdict that is set stands: a late window answer (any body) does not turn it into "use the API"
for what, outcome, verdict in [
    ("terminal", {"kind": "terminal", "status": 403, "error": "forbidden"}, {"kind": "terminal", "status": 403, "error": "forbidden"}),
    ("restart", {"kind": "restart"}, {"kind": "restart"}),
]:
    for late_what, late in [("undecodable", "{not json"), ("valid", json.dumps(window(0, 3, None)))]:
        steps = [poll(T0, req(None, 0, 8, False)), {"op": "window_failed", "now": T0, "outcome": outcome},
                 poll(T0, {"kind": "stop", "verdict": verdict}),
                 {"op": "window_answered", "now": T0, "body": late, "expect": "unexpected"},
                 poll(T0, {"kind": "stop", "verdict": verdict})]
        scenarios.append({"name": f"a late {late_what} window answer does not replace a {what} verdict", "discovery": "std", "seed": 7, "steps": steps})

# ───────────── A1 (clients plan, decisions D19, D23, D25): the storage breaker, the byte cap, the clock ─────────────
RENEWED = lambda n, i=0: {"kind": "fetch", "index": i, "url": f"{S3}/bb-01/t/v/{i}.bin?X-Amz-Signature=R{n}SIG{i}", "length": G[i]}


def renewal_answer(n, i=0):
    return {**window(i, 1, i + 1 if i < 2 else None), "grants": [grant(i, G[i], f"R{n}SIG")]}


# 15. storage that never answers: the first chunk to use up its renewals trips the breaker; the rest goes to the pinned route
steps = [poll(T0, req(None, 0, 8, False)), {"op": "window_answered", "now": T0, "response": window(0, 3, None), "expect": "ok"},
         poll(T0, fetch(0)), poll(T0, fetch(1)), poll(T0, fetch(2)), {"op": "storage_given_up", "expect": False}]
now = T0
for n in range(1, 4):
    steps += [{"op": "fetch_failed", "index": 0, "now": now, "expect": "ok"}, {"op": "storage_given_up", "expect": False}]
    now += 10_000  # past any backoff (cap 8 s)
    steps += [poll(now, req(VER, 0, 1, True)),
              {"op": "window_answered", "now": now, "response": renewal_answer(n), "expect": "ok"},
              poll(now, RENEWED(n))]
steps += [{"op": "fetch_failed", "index": 0, "now": now, "expect": "ok"}, {"op": "storage_given_up", "expect": True},
          poll(now, api(0)),
          # chunks 1 and 2 were still waiting on storage: their failures go straight to the pinned route, no renewals
          {"op": "fetch_failed", "index": 1, "now": now, "expect": "ok"}, {"op": "fetch_failed", "index": 2, "now": now, "expect": "ok"},
          poll(now, api(1)), poll(now, api(2)), poll(now, WAIT_NONE)]
for i in range(3):
    steps += [{"op": "fetch_ok", "index": i, "expect": "ok"}, {"op": "consumed", "index": i, "expect": "ok"}]
steps += [poll(now, DONE), {"op": "storage_given_up", "expect": True}]
scenarios.append({"name": "storage that never answers trips the breaker after the first exhausted chunk", "discovery": "std", "seed": 7, "steps": steps})

# 16. one success from storage first: the per-chunk rules alone apply, as before the breaker existed
steps = [poll(T0, req(None, 0, 8, False)), {"op": "window_answered", "now": T0, "response": window(0, 3, None), "expect": "ok"},
         poll(T0, fetch(0)), poll(T0, fetch(1)), poll(T0, fetch(2)),
         {"op": "fetch_ok", "index": 0, "expect": "ok"}, {"op": "consumed", "index": 0, "expect": "ok"}]
now = T0
for n in range(1, 4):
    steps += [{"op": "fetch_failed", "index": 1, "now": now, "expect": "ok"}]
    now += 10_000
    steps += [poll(now, req(VER, 1, 1, True)),
              {"op": "window_answered", "now": now, "response": renewal_answer(n, 1), "expect": "ok"},
              poll(now, RENEWED(n, 1))]
steps += [{"op": "fetch_failed", "index": 1, "now": now, "expect": "ok"}, poll(now, api(1)), {"op": "storage_given_up", "expect": False},
          {"op": "fetch_ok", "index": 2, "expect": "ok"}, {"op": "fetch_ok", "index": 1, "expect": "ok"},
          {"op": "consumed", "index": 1, "expect": "ok"}, {"op": "consumed", "index": 2, "expect": "ok"}, poll(now, DONE),
          {"op": "storage_given_up", "expect": False}]
scenarios.append({"name": "after one chunk from storage, the failures of another chunk do not trip the breaker", "discovery": "std", "seed": 7, "steps": steps})

# 16b. a chunk already in flight when the breaker trips arrives from storage: the report is cleared (no hold for the next file)
steps = [poll(T0, req(None, 0, 8, False)), {"op": "window_answered", "now": T0, "response": window(0, 3, None), "expect": "ok"},
         poll(T0, fetch(0)), poll(T0, fetch(1)), poll(T0, fetch(2))]
now = T0
for n in range(1, 4):
    steps += [{"op": "fetch_failed", "index": 0, "now": now, "expect": "ok"}]
    now += 10_000
    steps += [poll(now, req(VER, 0, 1, True)),
              {"op": "window_answered", "now": now, "response": renewal_answer(n), "expect": "ok"},
              poll(now, RENEWED(n))]
steps += [{"op": "fetch_failed", "index": 0, "now": now, "expect": "ok"}, {"op": "storage_given_up", "expect": True},
          {"op": "fetch_ok", "index": 1, "expect": "ok"}, {"op": "storage_given_up", "expect": False},
          poll(now, api(0)), {"op": "fetch_failed", "index": 2, "now": now, "expect": "ok"}, poll(now, api(2))]
for i in range(3):
    steps += [{"op": "fetch_ok", "index": i, "expect": "ok"} for _ in [0] if i != 1]
    steps += [{"op": "consumed", "index": i, "expect": "ok"}]
steps += [poll(now, DONE), {"op": "storage_given_up", "expect": False}]
scenarios.append({"name": "a chunk already in flight when the breaker trips arrives from storage: the report is cleared", "discovery": "std", "seed": 7, "steps": steps})

# 17. the byte cap (decision D23): the reorder window is the cap divided by the CIPHERTEXT chunk length (stride + 28), clamped to 1..4
MIB = 1024 * 1024


def geo(chunk_count, stride):
    original = stride * (chunk_count - 1) + stride // 2
    return {"chunk_count": chunk_count, "chunk_size": stride, "encrypted_size": original + 28 * chunk_count, "original_size": original}


def glen(g, i):
    full = g["chunk_size"] + 28
    return full if i + 1 < g["chunk_count"] else g["encrypted_size"] - full * (g["chunk_count"] - 1)


def gwindow(g, start, count, sig="SIG"):
    n = g["chunk_count"]
    end = min(start + count, n)
    return {"transport": "object-download-v1", "file_id": FILE, "object_version_id": VER, "chunk_count": n, "chunk_size": g["chunk_size"],
            "encrypted_size": g["encrypted_size"], "original_size": g["original_size"],
            "grants": [{"index": i, "method": "GET", "url": f"{S3}/bb-01/t/v/{i}.bin?X-Amz-Signature={sig}{i}", "length": glen(g, i), "expires_at": EXP300}
                       for i in range(start, end)],
            "next_index": end if end < n else None}


def gfetch(g, i, sig="SIG"):
    return {"kind": "fetch", "index": i, "url": f"{S3}/bb-01/t/v/{i}.bin?X-Amz-Signature={sig}{i}", "length": glen(g, i)}


def cap_scenario(name, stride, cap, starts):
    g = geo(10, stride)
    steps = [poll(T0, req(None, 0, 8, False)), {"op": "window_answered", "now": T0, "response": gwindow(g, 0, 8), "expect": "ok"}]
    steps += [poll(T0, gfetch(g, i)) for i in range(starts)] + [poll(T0, WAIT_NONE)]
    sc = {"name": name, "discovery": "std", "seed": 7, "steps": steps}
    if cap is not None:
        sc["max_in_flight_bytes"] = cap
    scenarios.append(sc)


cap_scenario("a 64 MiB cap holds four chunks of 4 MiB", 4 * MIB, 64 * MIB, 4)
cap_scenario("a 64 MiB cap holds three chunks of 16 MiB: the 28 bytes of overhead count", 16 * MIB, 64 * MIB, 3)
cap_scenario("a 64 MiB cap holds one chunk of 64 MiB", 64 * MIB, 64 * MIB, 1)
cap_scenario("a 64 MiB cap still holds one chunk of 256 MiB", 256 * MIB, 64 * MIB, 1)
cap_scenario("no cap keeps the window of four", 4 * MIB, None, 4)
cap_scenario("a cap of exactly two ciphertext chunks holds two", 1000, 2 * 1028, 2)
cap_scenario("a cap one byte short of two ciphertext chunks holds one", 1000, 2 * 1028 - 1, 1)
cap_scenario("a cap of zero still holds one", 1000, 0, 1)

# 18. with a cap of one, a failing chunk blocks the next fetch until it is consumed
g256 = geo(10, 256 * MIB)
steps = [poll(T0, req(None, 0, 8, False)), {"op": "window_answered", "now": T0, "response": gwindow(g256, 0, 8), "expect": "ok"},
         poll(T0, gfetch(g256, 0)), poll(T0, WAIT_NONE),
         {"op": "fetch_failed", "index": 0, "now": T0 + 1000, "expect": "ok"},
         poll(T0 + 1000, {"kind": "wait", "until_ms_between": [T0 + 1125, T0 + 1250]}),
         poll(T0 + 1250, req(VER, 0, 1, True)),
         {"op": "window_answered", "now": T0 + 1250, "response": gwindow(g256, 0, 1, "NEWSIG"), "expect": "ok"},
         poll(T0 + 1250, gfetch(g256, 0, "NEWSIG")),
         poll(T0 + 1250, WAIT_NONE),  # chunk 1 holds a grant but is not started: it would be held, 256 MiB, behind a stalled chunk
         {"op": "fetch_ok", "index": 0, "expect": "ok"}, poll(T0 + 1250, WAIT_NONE),
         {"op": "consumed", "index": 0, "expect": "ok"}, poll(T0 + 1250, gfetch(g256, 1))]
scenarios.append({"name": "with a cap of one, a failing chunk blocks the next fetch", "discovery": "std", "seed": 7, "max_in_flight_bytes": 64 * MIB, "steps": steps})

# 19. a client clock ten minutes off (decision D28: no skew correction in v1) costs what it costs today
for what, offset in (("ahead", 600_000), ("behind", -600_000)):
    t = T0 + offset
    steps = [poll(t, req(None, 0, 8, False)), {"op": "window_answered", "now": t, "response": window(0, 3, None), "expect": "ok"},
             poll(t, fetch(0)), poll(t, fetch(1)), poll(t, fetch(2))]
    for i in range(3):
        steps += [{"op": "fetch_ok", "index": i, "expect": "ok"}, {"op": "consumed", "index": i, "expect": "ok"}]
    steps += [poll(t, DONE)]
    scenarios.append({"name": f"a client clock ten minutes {what} still completes a file with one window request", "discovery": "std", "seed": 7, "steps": steps})
    # and its links last 270 s from arrival by the client's own clock, whatever the server wrote in expires_at
    steps = [poll(t, req(None, 0, 8, False)), {"op": "window_answered", "now": t, "response": window(0, 3, None), "expect": "ok"},
             poll(t + 269_999, fetch(0)), poll(t + 270_000, req(VER, 1, 2, True))]
    scenarios.append({"name": f"a client clock ten minutes {what}: grants last 270 s from arrival by that clock", "discovery": "std", "seed": 7, "steps": steps})

# ───────────── DirectHealth (decision D19) ─────────────
HTTL = 600_000
health = []


def hs(op, direction, now=None, expect=None, **kw):
    step = {"op": op, "direction": direction}
    if now is not None:
        step["now"] = now
    if expect is not None or op == "last_gave_up":
        step["expect"] = expect  # an explicit null means "nothing recorded"
    step.update(kw)
    return step


health.append({"name": "a give-up holds new transfers of that direction off for ten minutes, then they may start", "steps": [
    hs("may_start", "upload", T0, True), hs("gave_up", "upload", T0),
    hs("may_start", "upload", T0, False), hs("may_start", "upload", T0 + HTTL - 1, False), hs("may_start", "upload", T0 + HTTL, True),
    hs("may_start", "download", T0 + 1, True)]})
health.append({"name": "downloads and uploads are held independently", "steps": [
    hs("gave_up", "download", T0), hs("may_start", "download", T0 + 1, False), hs("may_start", "upload", T0 + 1, True),
    hs("last_gave_up", "download", expect=T0), hs("last_gave_up", "upload", expect=None),
    hs("gave_up", "upload", T0 + 5), hs("last_gave_up", "download", expect=T0), hs("last_gave_up", "upload", expect=T0 + 5)]})
health.append({"name": "a later give-up renews the hold", "steps": [
    hs("gave_up", "upload", T0), hs("gave_up", "upload", T0 + HTTL - 1),
    hs("may_start", "upload", T0 + HTTL + 5, False), hs("may_start", "upload", T0 + 2 * HTTL - 1, True)]})
health.append({"name": "a file that gave up direct stays off it, with no hold recorded at all", "steps": [
    hs("may_start_file", "upload", T0, True, file_gave_up=False), hs("may_start_file", "upload", T0, False, file_gave_up=True),
    hs("may_start_file", "download", T0 + 10 * HTTL, False, file_gave_up=True)]})
health.append({"name": "the file's bit and the hold both apply", "steps": [
    hs("gave_up", "download", T0), hs("may_start_file", "download", T0 + 1, False, file_gave_up=False),
    hs("may_start_file", "download", T0 + HTTL, True, file_gave_up=False), hs("may_start_file", "download", T0 + HTTL, False, file_gave_up=True)]})
health.append({"name": "a restored timestamp behaves like a live one", "steps": [
    hs("restore", "download", ms=T0), hs("last_gave_up", "download", expect=T0),
    hs("may_start", "download", T0 + HTTL - 1, False), hs("may_start", "download", T0 + HTTL, True), hs("last_gave_up", "upload", expect=None)]})
health.append({"name": "a recorded time in the future counts as expired", "steps": [
    hs("restore", "upload", ms=T0 + 5000), hs("may_start", "upload", T0, True),
    hs("gave_up", "download", 9_000_000_000_000_000), hs("may_start", "download", T0, True)]})
health.append({"name": "a clock that stepped back does not extend a hold", "steps": [
    hs("gave_up", "upload", T0), hs("may_start", "upload", T0 + 1, False), hs("may_start", "upload", T0 - 1, True)]})

# ───────────── resume_transport (decision D25) ─────────────
resume_transport = []


def rt(name, recorded, discovery, forced, expect):
    resume_transport.append({"name": name, "recorded": recorded, "discovery": discovery, "forced_api": forced, "expect": expect})


OFFERS = {"kind": "offers", "upload": True}
for d, nm in ((OFFERS, "offers upload"), ({"kind": "offers", "upload": False}, "lists no upload"), ({"kind": "not_supported"}, "says not supported"),
              ({"kind": "unknown"}, "could not be read"), ({"kind": "unauthorized"}, "refused the login")):
    for forced in (False, True):
        rt(f"an API session continues on the API: discovery {nm}, forced={forced}", "api", d, forced, "continue_api")
rt("a direct session continues direct when discovery offers upload", "direct", OFFERS, False, "continue_direct")
rt("a direct session is given up when discovery lists no upload", "direct", {"kind": "offers", "upload": False}, False, "abandon_to_api")
rt("a direct session is given up when the server says it has no direct transfer (a JSON 404)", "direct", {"kind": "not_supported"}, False, "abandon_to_api")
rt("a direct session is kept and the file fails when discovery cannot be read (a 5xx, a timeout, a bare 404)", "direct", {"kind": "unknown"}, False, "keep_record_and_fail")
rt("a direct session is kept and the user signs in again on a 401 or 403 from discovery", "direct", {"kind": "unauthorized"}, False, "keep_record_and_reauthenticate")
for d, nm in ((OFFERS, "offers upload"), ({"kind": "offers", "upload": False}, "lists no upload"), ({"kind": "not_supported"}, "says not supported"),
              ({"kind": "unknown"}, "could not be read"), ({"kind": "unauthorized"}, "refused the login")):
    rt(f"forcing the API gives a direct session up whatever discovery says: {nm}", "direct", d, True, "abandon_to_api")


# 20. K1: the storage-answer check every client applies to a storage GET (clients design 6.4:
# the web used to accept status === 200 alone).
CHUNK = 4 * MIB + 28
storage_get = [
    {"name": "a 200 with the grant's length is the chunk", "status": 200, "content_length": CHUNK, "expected": CHUNK,
     "expect": {"kind": "stored"}, "source": "spec R1.7: a chunk is a 200 whose length is the grant's length"},
    {"name": "a 200 one byte short is not the chunk", "status": 200, "content_length": CHUNK - 1, "expected": CHUNK,
     "expect": {"kind": "failed", "status": 200}, "source": "spec R1.7: a short body never authenticates as the chunk"},
    {"name": "a 200 one byte long is not the chunk", "status": 200, "content_length": CHUNK + 1, "expected": CHUNK,
     "expect": {"kind": "failed", "status": 200}, "source": "spec R1.7: the length must be exact"},
    {"name": "a 200 with no Content-Length is not the chunk", "status": 200, "content_length": None, "expected": CHUNK,
     "expect": {"kind": "failed", "status": 200}, "source": "spec R1.7: a missing length cannot be checked, so it is a failure"},
    {"name": "a 206 partial answer is not the chunk", "status": 206, "content_length": CHUNK, "expected": CHUNK,
     "expect": {"kind": "failed", "status": 206}, "source": "client-side case: a proxy or a Range answer, no server route sends 206"},
    {"name": "a 302 redirect is not the chunk", "status": 302, "content_length": CHUNK, "expected": CHUNK,
     "expect": {"kind": "failed", "status": 302}, "source": "client-side case: storage redirects are refused (clients 3.1)"},
    {"name": "a 403 is not the chunk", "status": 403, "content_length": CHUNK, "expected": CHUNK,
     "expect": {"kind": "failed", "status": 403}, "source": "server: storage refuses an expired or wrong signature (S3 error body, never JSON)"},
    {"name": "a 500 is not the chunk", "status": 500, "content_length": 0, "expected": CHUNK,
     "expect": {"kind": "failed", "status": 500}, "source": "server: storage's own 5xx, a proxy's page"},
    {"name": "no answer at all keeps status 0", "status": 0, "content_length": None, "expected": CHUNK,
     "expect": {"kind": "failed", "status": 0}, "source": "client-side case: a network failure or timeout (no HTTP status)"},
    {"name": "a 200 with a zero length for an empty expectation is stored", "status": 200, "content_length": 0, "expected": 0,
     "expect": {"kind": "stored"}, "source": "spec R1.7: the rule is exactness, and an empty chunk is exact at zero"},
    {"name": "a counted body one byte short is not the chunk", "check": "body", "received": CHUNK - 1, "expected": CHUNK,
     "expect": {"kind": "failed", "status": 200},
     "source": "spec R1.7: a truncated stream ends short even after a 200 head with the grant's length"},
    {"name": "a counted body one byte long is not the chunk", "check": "body", "received": CHUNK + 1, "expected": CHUNK,
     "expect": {"kind": "failed", "status": 200},
     "source": "spec R1.7: a proxy that sends more than it declares is still not the chunk"},
    {"name": "a counted body of exactly the grant is the chunk", "check": "body", "received": CHUNK, "expected": CHUNK,
     "expect": {"kind": "stored"}, "source": "spec R1.7: the caller counts what it read; equal is the chunk"},
]

# 20b. K2 follow-up: the counted body as a stream (StorageBody), not only as one count. The head is
# good in every row; the pushes are what the caller read.
storage_body = [
    {"name": "pushes that add up to the grant are the chunk", "status": 200, "content_length": CHUNK,
     "expected": CHUNK, "pushes": [CHUNK], "expect": {"kind": "stored"},
     "source": "spec R1.7: the caller counts what it read; equal is the chunk"},
    {"name": "a stream read in two pushes is still the chunk", "status": 200, "content_length": CHUNK,
     "expected": CHUNK, "pushes": [CHUNK // 2, CHUNK - CHUNK // 2], "expect": {"kind": "stored"},
     "source": "spec R1.7: the count is the sum of what arrived, not the shape of the reads"},
    {"name": "a push that would pass the grant is refused at once", "status": 200, "content_length": CHUNK,
     "expected": CHUNK, "pushes": [CHUNK - 1, 2], "expect": {"kind": "failed", "status": 200},
     "source": "spec R1.7: a proxy that sends more than it declared is not the chunk; the count stops at the grant"},
    {"name": "pushes that end short are not the chunk", "status": 200, "content_length": CHUNK,
     "expected": CHUNK, "pushes": [CHUNK - 1], "expect": {"kind": "failed", "status": 200},
     "source": "spec R1.7: a truncated stream ends short even after a 200 head with the grant's length"},
    {"name": "an empty chunk is stored with no pushes", "status": 200, "content_length": 0,
     "expected": 0, "pushes": [], "expect": {"kind": "stored"},
     "source": "spec R1.7: the rule is exactness, and an empty chunk is exact at zero"},
    {"name": "a zero-byte push never moves the count", "status": 200, "content_length": CHUNK,
     "expected": CHUNK, "pushes": [0, CHUNK, 0], "expect": {"kind": "stored"},
     "source": "spec R1.7: a read of nothing changes no count"},
]

# 21. K1: pacing, desktop's formula with its four own test rows (direct_download.rs:194-199 and :1538-1544).
pacing = [
    {"name": "no ceiling means no wait", "start_ms": 1_000, "wire_bytes": 10_000, "kbps": 0,
     "expect": "-9223372036854775808", "source": "desktop src-tauri/src/direct_download.rs:1540 (the ceiling is off: i64::MIN; the formula is :193-199)"},
    {"name": "no bytes received yet is no wait", "start_ms": 1_000, "wire_bytes": 0, "kbps": 8,
     "expect": 1_000, "source": "desktop src-tauri/src/direct_download.rs:1542"},
    {"name": "8 KiB at 8 KiB/s is one second", "start_ms": 1_000, "wire_bytes": 8 * 1024, "kbps": 8,
     "expect": 2_000, "source": "desktop src-tauri/src/direct_download.rs:1542"},
    {"name": "the largest count saturates instead of wrapping", "start_ms": 0, "wire_bytes": "18446744073709551615", "kbps": 1,
     "expect": "9223372036854775807", "source": "desktop src-tauri/src/direct_download.rs:1543 (u64::MAX at 1 KiB/s)"},
    {"name": "a 4 MiB chunk at 1000 KiB/s takes four seconds", "start_ms": T0, "wire_bytes": CHUNK, "kbps": 1000,
     "expect": T0 + 4_096, "source": "client policy: the formula, clients 6.3 (pacing moves out of desktop)"},
    {"name": "less than a millisecond is no wait", "start_ms": 500, "wire_bytes": 1, "kbps": 1,
     "expect": 500, "source": "client policy: integer division floors a started millisecond count"},
    {"name": "a negative start is kept", "start_ms": -1_000, "wire_bytes": 1024, "kbps": 1,
     "expect": 0, "source": "client policy: a monotonic clock before its epoch still adds the wait"},
]

# 22. K1: the storage allowlist rule (clients design 6.4: the web compared this in TypeScript).
_storage_all = [{"host": "s3.storage.test", "bucket": "bb-01"}, {"host": "s3.storage.test", "bucket": "bb-02"},
                {"host": "eu.storage.test", "bucket": "vault"}]
pairs_allowed = [
    {"name": "all three pairs allowlisted and download offered", "discovery": "std", "direction": "download",
     "allowlist": _storage_all, "expect": True, "source": "spec R1.12: every listed pair must be one the client may use"},
    {"name": "one pair missing from the allowlist", "discovery": "std", "direction": "download",
     "allowlist": _storage_all[:2], "expect": False, "source": "spec R1.12: a discovery pair the CSP lacks turns direct off"},
    {"name": "hosts compare ASCII case-insensitively", "discovery": "std", "direction": "download",
     "allowlist": [{"host": "S3.STORAGE.TEST", "bucket": "bb-01"}, {"host": "S3.STORAGE.TEST", "bucket": "bb-02"},
                   {"host": "EU.STORAGE.TEST", "bucket": "vault"}],
     "expect": True, "source": "spec R1.12: DNS names are case-insensitive"},
    {"name": "buckets compare exactly", "discovery": "std", "direction": "download",
     "allowlist": [{"host": "s3.storage.test", "bucket": "BB-01"}, {"host": "s3.storage.test", "bucket": "bb-02"},
                   {"host": "eu.storage.test", "bucket": "vault"}],
     "expect": False, "source": "spec R1.12: S3 bucket names are case-sensitive"},
    {"name": "download is allowed for std", "discovery": "std", "direction": "download", "allowlist": _storage_all,
     "expect": True, "source": "spec R1.13: the token must be offered and the pairs allowlisted"},
    {"name": "upload is not offered by std", "discovery": "std", "direction": "upload", "allowlist": _storage_all,
     "expect": False, "source": "spec R1.13: a direction the server does not offer is never allowed"},
    {"name": "an empty allowlist refuses every listed pair", "discovery": "std", "direction": "download",
     "allowlist": [], "expect": False, "source": "spec R1.12: nothing listed, nothing allowed"},
    {"name": "an empty allowlist is not allowed vacuously", "discovery": "hosts_only", "direction": "download",
     "allowlist": [], "expect": False,
     "source": "spec R1.12: every pair (of none) is allowlisted, but direct needs a listed bucket and check_storage_url "
               "refuses every unlisted bucket; the web rule is the same "
               "(!!discovery.storage_buckets?.length && every(...))"},
    {"name": "a discovery with no buckets is not allowed", "discovery": "hosts_only", "direction": "download",
     "allowlist": [{"host": "s3.storage.test", "bucket": "bb-01"}], "expect": False,
     "source": "spec R1.12: no listed bucket leaves no storage route, whatever the allowlist says (the vacuous "
               "`every` bug: offered && buckets.iter().all(listed) is true for no buckets)"},
    {"name": "both dev pairs allowlisted", "discovery": "dev", "direction": "download",
     "allowlist": [{"host": "127.0.0.1:9000", "bucket": "bb-dev"}, {"host": "localhost:9000", "bucket": "bb-dev"}],
     "expect": True, "source": "spec R1.12: a loopback development pair is still a pair"},
    {"name": "one dev pair missing", "discovery": "dev", "direction": "download",
     "allowlist": [{"host": "127.0.0.1:9000", "bucket": "bb-dev"}],
     "expect": False, "source": "spec R1.12: the discovery answer names a pair the allowlist lacks"},
    {"name": "extra pairs in the allowlist do not hurt", "discovery": "std", "direction": "download",
     "allowlist": _storage_all + [{"host": "other.storage.test", "bucket": "spare"}],
     "expect": True, "source": "spec R1.12: the rule is every discovery pair, not only the allowlist"},
    {"name": "a discovery with no tokens is never allowed", "discovery": "no_tokens", "direction": "download",
     "allowlist": [{"host": "s3.storage.test", "bucket": "bb-01"}], "expect": False,
     "source": "spec R1.13: the discovery lists buckets but no download token"},
]

# 23. K1: the memory classes and their byte caps (clients design 6.4: the web's 64 MiB policy).
memory_class = [
    {"name": "native holds 256 MiB", "class": "native", "expect": 256 * MIB,
     "source": "clients design 6.4 / D23: CLI and desktop"},
    {"name": "browser holds 64 MiB", "class": "browser", "expect": 64 * MIB,
     "source": "clients design 6.4 / D23: the web's 64 MiB in-flight policy"},
    {"name": "a mobile app holds 64 MiB", "class": "mobile_app", "expect": 64 * MIB,
     "source": "clients design 6.4 / D23: iOS and Android foreground"},
    {"name": "a mobile extension holds 16 MiB", "class": "mobile_extension", "expect": 16 * MIB,
     "source": "clients design 6.4 / D23: the File Provider and backup extension"},
]

out = {
    "_provenance": "Task 2173 contract vectors for beebeeb_core::direct_transfer. Hand-authored from the spec "
                   "(R1.6, R1.12, R1.13, R2.6) and the core #33 review, not generated from the code. "
                   "One interpreter, beebeeb_core::direct_transfer::vectors (test-support), is run by "
                   "beebeeb-core, the beebeeb-wasm seams and the beebeeb-uniffi exports.",
    "version": 1,
    "t0_ms": T0,
    "file_id": FILE,
    "discoveries": discoveries,
    "authority": authority,
    "classify": classify,
    "redact": redact,
    "scrub": scrub,
    "chunk_length": geometry,
    "storage_get": storage_get,
    "storage_body": storage_body,
    "pacing": pacing,
    "pairs_allowed": pairs_allowed,
    "memory_class": memory_class,
    "pinned_retry": pinned_retry,
    "discovery_cache": cache,
    "planner": scenarios,
    "health": health,
    "resume_transport": resume_transport,
}
json.dump(out, open(sys.argv[1], "w", encoding="utf-8"), indent=2, ensure_ascii=False)
print("rows: authority", len(authority), "classify", len(classify), "pinned_retry", len(pinned_retry), "cache scenarios", len(cache), "planner scenarios", len(scenarios), "health", len(health), "resume_transport", len(resume_transport), "storage_get", len(storage_get), "storage_body", len(storage_body), "pacing", len(pacing), "pairs_allowed", len(pairs_allowed), "memory_class", len(memory_class))
