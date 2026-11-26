# Limitations

What crawl-signer doesn't do, and what to do about it.

## Rates and crawl delay

crawl-signer paces requests to an origin only by its `Crawl-delay`, capped at
[`max_crawl_delay_seconds`](../reference/config.md#max_crawl_delay_seconds): a request that comes too soon is refused
with `429 crawl-delay` and a `Retry-After`, not held back. Your crawlers' scheduler retries it. An origin without
`Crawl-delay` gets no limit, and neither does the gateway overall.

The pacing is per crawl-signer instance and in memory. Two instances in front of the same origins let through two
requests per delay, and a restart forgets when the last request went. Keep request rates in your crawlers' scheduler,
or add Envoy's
[local rate limit](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/local_rate_limit_filter)
filter.

## Resolved addresses

crawl-signer refuses internal addresses written in the URL, but sees names, not the addresses they resolve to. A
hostname that resolves to `10.0.0.1` passes it. Stop Envoy from connecting to internal ranges with the host's
firewall: [Deploy with Envoy](../guides/deploy-with-envoy.md#3-restrict-what-envoy-can-reach).

## Methods and protocols

Only `GET` and `HEAD` without a body, over HTTP/1.1 from the caller and to the origin. No `CONNECT`, so a caller can't
open a tunnel, and no WebSockets.

## Replay

A Web Bot Auth signature covers the host, not the path, and has no nonce. Whoever sees a signed request, such as the
origin, can send other requests to the same host with it until it expires, at most 60 seconds later. Those come from
their own address, not the gateway's. This is a property of Web Bot Auth as verifiers implement it.

## robots.txt changes

A change to an origin's robots.txt applies when the cached copy expires: after its `max-age`, at most 24 hours. There
is no way to flush the cache other than restarting crawl-signer.

## Configuration and keys

crawl-signer reads its configuration and its key once, at startup. To rotate a key or change a setting, restart it;
Envoy refuses requests during the restart, which takes well under a second. Run two instances behind one Envoy
cluster if that matters to you.

## The key directory

The directory crawl-signer serves with [`directory_listen`](../reference/config.md#directory_listen) lists only the key
it signs with. A key rotation needs both keys listed for a while, so serve the directory from your site for that
time: [Become a verified bot](../guides/become-a-verified-bot.md#serve-it-yourself).

## Signature components

Signatures cover `@authority` and `signature-agent` only, which is what Web Bot Auth requires. crawl-signer can't be
configured to cover more, such as `@path` or a nonce.
