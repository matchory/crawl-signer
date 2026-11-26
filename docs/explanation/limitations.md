# Limitations

What crawl-signer doesn't do, and what to do about it.

## Rates and crawl delay

crawl-signer doesn't limit how fast requests go out, per origin or overall, and ignores `Crawl-delay`, which RFC 9309
doesn't define. Keep request rates in your crawlers' scheduler, or add Envoy's
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

crawl-signer signs requests, not your key directory: you publish and sign that yourself.
[Become a verified bot](../guides/become-a-verified-bot.md) shows how.

## Signature components

Signatures cover `@authority` and `signature-agent` only, which is what Web Bot Auth requires. crawl-signer can't be
configured to cover more, such as `@path` or a nonce.
