# Metrics

With [`metrics_listen`](config.md#metrics_listen) set, crawl-signer serves these at `/metrics` in the Prometheus text
format, along with the Go runtime's and the process's standard metrics (`go_*`, `process_*`).

| Metric | Type | Labels | Meaning |
| --- | --- | --- | --- |
| `crawl_signer_requests_total` | counter | `verdict` | Requests, by [verdict](envoy-interface.md#a-request-it-refuses): `ok` or the refusal's reason |
| `crawl_signer_robots_cache_hits_total` | counter | | robots.txt checks answered from a cached entry that hadn't expired |
| `crawl_signer_robots_cache_misses_total` | counter | | robots.txt checks that needed a fetch |
| `crawl_signer_robots_fetch_total` | counter | `outcome` | robots.txt fetches, by `2xx`, `3xx`, `4xx`, `5xx` or `error` (no answer, a refusal by the gateway, too many redirects) |
| `crawl_signer_robots_cache_entries` | gauge | | Origins in the robots.txt cache |
| `crawl_signer_robots_cache_bytes` | gauge | | Estimated size of the cached rules, against [`robots_cache_bytes`](config.md#robots_cache_bytes) |
| `crawl_signer_sign_total` | counter | `result` | Calls to the signing key, by `ok` or `error` |
| `crawl_signer_sign_seconds` | histogram | | Duration of calls to the signing key |

`crawl_signer_sign_total` has both labels from the start, so a `rate()` sees the first error. A call to the signing
key happens once per authority and signature window, not once per request: see
[Signatures](../explanation/signatures.md#caching).

Envoy's own statistics complement these: `ext_proc` errors and timeouts appear under
`http.<stat_prefix>.ext_proc.*` on Envoy's admin interface.
