# Troubleshoot

Start from what the caller got back. A refusal by the gateway has an `X-Crawl-Gateway-Refusal` header; an answer
without it came from the origin or from Envoy.

```bash
curl -sS -D - -o /dev/null --proxy http://127.0.0.1:3128 http://example.com/page
```

## Refused by crawl-signer

The header's value is the reason. [Envoy interface](../reference/envoy-interface.md#a-request-it-refuses) lists every
reason and its status.

### `robots` for a path you expected to be allowed

Fetch the origin's robots.txt and find the group for your [`robots_agent`](../reference/config.md#robots_agent),
or `*` if no group names it:

```bash
curl -sS https://example.com/robots.txt
```

Only one group applies. A group for your product token replaces the `*` group entirely, so a `Disallow` under `*`
doesn't apply to you once a group names your bot, and an `Allow` under `*` doesn't either. If the origin changed its
robots.txt, crawl-signer applies the change when its copy expires, at most 24 hours later; restarting crawl-signer
drops every copy.

### `robots-unavailable`

The origin's robots.txt answered 429 or 5xx, or didn't answer, and crawl-signer has no copy from the last 30 days.
`crawl_signer_robots_fetch_total` shows which, and crawl-signer logs nothing per fetch. Try the fetch as the gateway
does, through the internal listener:

```bash
sudo -u crawl-signer curl -sS -D - -o /dev/null --unix-socket /run/envoy/internal.sock \
  http://example.com/robots.txt
```

A refusal header in that answer means the gateway refused its own fetch, and its reason tells you why. Otherwise the
status is the origin's. crawl-signer retries after 5 minutes, doubling up to an hour.

### `crawl-delay`

The origin's robots.txt has a `Crawl-delay`, and the last request through the gateway to it was more recent than that.
Wait for `Retry-After` seconds and send it again. Many of these from one origin mean your scheduler sends to it faster
than it asks for; pace it there, so requests aren't refused. If several callers share the gateway, they share each
origin's delay.

### `signing`

The signing key gave no signature within 2 seconds. With Transit, check that the address in
[`signing_key.transit`](../reference/config.md#signing_keytransit) answers and that the token can sign:

```bash
curl -sS --unix-socket /run/crawl-signer-bao/bao.sock -X POST \
  -d '{"input":"dGVzdA=="}' http://transit/v1/transit/sign/web-bot-auth
```

A `403` is the policy; a timeout or `connection refused` is the server or proxy.
`crawl_signer_sign_total{result="error"}` counts the failures.

### `method` or `port` for a site that exists

The caller probably sent an `https://` URL, which clients send as a `CONNECT` tunnel and the gateway refuses as
`method`, or an `http://` URL with `:443`, which is the wrong port for http. Send `http://example.com/page`; the
gateway fetches it over https. For a site that only speaks plain http, add `X-Crawl-Scheme: http`.

## Refused by Envoy

### `404` with response flag `NR`

Envoy matched no route after crawl-signer answered. The route configuration differs from the example: each route
must match `prefix: /`, and `x-forwarded-proto` must still be on the request when the route is chosen. Remove it in
the route's `request_headers_to_remove`, not before.

### `500` for every request

Envoy can't reach crawl-signer, and `failure_mode_allow: false` refuses the request. Check that crawl-signer runs,
that its socket exists at the path the `crawl_signer` cluster names, and that Envoy's user can open it:

```bash
systemctl status crawl-signer
sudo -u envoy test -w /run/crawl-signer/grpc.sock && echo ok
```

### `503` with response flag `UF` or `URX`

Envoy couldn't connect to the origin: DNS, the host firewall, or the origin itself. Envoy's access log names the
upstream host it tried.

## crawl-signer doesn't start

It prints the reason and exits. The common ones:

| Message | Cause |
| --- | --- |
| `json: unknown field "…"` | A misspelt or removed field; see [Configuration](../reference/config.md) |
| `user_agent must contain robots_agent` | Site operators couldn't tell which robots.txt group applies to you |
| `signing_key.keyid is …, but the private key's thumbprint is …` | The configured `keyid` belongs to another key; remove it or fix it |
| `environment variable … is not set` | The data source's variable is missing from crawl-signer's environment |
| `bind: address already in use` | Another process has [`metrics_listen`](../reference/config.md#metrics_listen) |
