# Security policy

## Reporting a vulnerability

Report vulnerabilities privately through GitHub's
[private vulnerability reporting](https://github.com/matchory/crawl-signer/security/advisories/new)
on matchory/crawl-signer. Do not open a public issue, pull request or
discussion for them.

Include what is affected, how to reproduce it, and the impact you expect. We
will confirm receipt, keep you informed while we work on a fix, and credit you
in the advisory unless you prefer otherwise.

Vulnerabilities in Envoy go to the
[Envoy project](https://github.com/envoyproxy/envoy/security/policy), and those
in OpenBao to the [OpenBao project](https://github.com/openbao/openbao/security/policy).

## Supported versions

Fixes go into the latest release. Older releases are not patched.

## Security model

crawl-signer makes the guarantees below, provided the environment properties
after them hold. Each guarantee names who it defends against and which
properties it relies on. Tests that verify a guarantee carry its ID
(`Guards: G1`); a check in the test suite fails if a guarantee listed here has
none.

A *caller* is a program that sends requests through the gateway. An *origin*
is a site the gateway sends them to.

### G1: Nothing reaches an origin unchecked or unsigned

Attackers: a caller; anyone who can make crawl-signer, its signing key or an
origin's robots.txt slow or unavailable.
Assumes: E1.

Envoy forwards a request only after crawl-signer has answered for it, and
crawl-signer lets a request through only after the rules (G2) and robots.txt
(G3) allowed it and it has a signature for it. When it can't decide, it
refuses:

- the signing key gives no signature within 2 seconds, and no unexpired
  signature for the authority is cached: `503 signing`;
- robots.txt can't be fetched and no usable copy is cached:
  `403 robots-unavailable`;
- crawl-signer itself doesn't answer: Envoy refuses the request (E1).

### G2: Only a GET or HEAD without a body, to a hostname or a public address on the scheme's default port

Attackers: a caller who wants to reach an internal service with the
gateway's identity, or to send anything but a fetch.
Assumes: E1, E3.

crawl-signer refuses:

- any method but `GET` and `HEAD` (`405 method`);
- a request with `Transfer-Encoding` or a `Content-Length` other than `0`
  (`413 body`);
- a port other than 443 for https or 80 for http (`403 port`);
- an `X-Crawl-Scheme` header other than one `http` (`403 scheme`);
- an authority with user information, an IPv6 zone, or a character outside
  letters, digits, `-`, `.` and `_` (`403 target`);
- `localhost` and its subdomains, and a literal address in a private,
  loopback, link-local, shared, benchmarking, multicast or reserved range,
  including IPv4 written as one number, in hex or octal, or embedded in IPv6
  (IPv4-mapped, IPv4-compatible, NAT64, 6to4 and Teredo) (`403 target`).

crawl-signer sees names, not the addresses they resolve to. A hostname that
resolves to an internal address is E3's to stop.

### G3: A path robots.txt disallows is not fetched

Attackers: a caller.
Assumes: E1.

crawl-signer applies the group of the origin's robots.txt that names the
configured product token, or the `*` group if none does, as RFC 9309 and
Google's parser select them. robots.txt is fetched for the scheme and
authority of each request, so `http://` and `https://`, and each host and
port, have their own.

- A 2xx answer's rules apply for its `Cache-Control: max-age`, held between 1
  and 24 hours, or 24 hours without one.
- A 4xx answer other than 429 means there are no rules, for 24 hours.
- A 429, 5xx, a timeout or an unreachable origin is a failure. The last 2xx
  copy applies while it is at most 30 days old; without one, every path but
  `/robots.txt` is refused. The next fetch waits 5 minutes, doubling with
  each failure to at most an hour.
- A request waits at most 10 seconds for a fetch, then uses the cached copy
  if any or is refused.

A change to an origin's robots.txt therefore applies once the cached copy
expires, at most 24 hours later.

### G4: A caller can't change the identity a request carries

Attackers: a caller.
Assumes: E1.

`User-Agent`, `From` (when configured), `Signature-Agent`, `Signature-Input`
and `Signature` are always the gateway's own. Every other header a caller
sends is removed unless it is one of `Accept`, `Accept-Encoding`,
`Accept-Language`, `If-Modified-Since`, `If-None-Match` and `Range`. This
removes cookies, credentials and forwarding headers. A caller chooses plain
http only with `X-Crawl-Scheme: http`, which crawl-signer removes; a caller's
`X-Crawl-Upstream` never reaches the route (E1).

### G5: A signature covers exactly the authority the request goes to, and names its key

Attackers: a caller; an origin that receives a signature and replays it
elsewhere.
Assumes: E4.

The signature covers `@authority` as Envoy forwards it, lowercased and
without the scheme's default port, and the `Signature-Agent` header. A byte
outside visible ASCII in the authority refuses the request, so a caller
can't add a line to the signed text. A signature is created on a 30-second
boundary and expires 60 seconds after it; a request always leaves with one
that is valid for at least 10 more seconds.

The `keyid` of a private key is its RFC 7638 thumbprint. A configured `keyid`
that differs from the thumbprint stops crawl-signer at startup, so the
signatures and the published key directory cannot name different keys.

### G6: Every request leaves a record of its verdict

Attackers: a caller who wants to act through the gateway unseen.
Assumes: E1.

Every answer carries Envoy dynamic metadata in the `crawl` namespace: the
caller, the verdict (`ok` or the refusal's reason), the robots.txt outcome
and the `keyid`. Every verdict increments `crawl_signer_requests_total`.

### G7: Only Envoy's configuration can exempt a request from robots.txt

Attackers: a caller.
Assumes: E1, E2.

crawl-signer skips robots.txt only for a request whose listener metadata has
`crawl.internal = true`: its own robots.txt fetches, which would otherwise
wait on themselves. No header or attribute a caller sends can set it, and a
request without the attribute is checked.

### G8: Requests to an origin are at least its Crawl-delay apart

Attackers: a caller.
Assumes: E1, E6.

crawl-signer reads `Crawl-delay` from the robots.txt group G3 applies, as
seconds between requests, fractions allowed; the largest value in the group
counts. A missing, negative or unparsable value means no delay. RFC 9309
doesn't define the field. The delay is capped at `max_crawl_delay_seconds`,
60 by default.

A request robots.txt allows, `/robots.txt` included, that comes less than the
delay after the last request crawl-signer let through to the same origin is
refused with `429 crawl-delay` and `Retry-After` set to the seconds left,
rounded up. A refused request doesn't move the next slot. crawl-signer holds
no request back, so it queues nothing. crawl-signer's own robots.txt fetches
(G7) aren't paced.

The pacing state is in memory: it starts empty when crawl-signer starts, and
for an origin dropped from the robots.txt cache.

### G9: The key directory signs nothing a requester chooses

Attackers: anyone who can reach `directory_listen`.
Assumes: E4.

The directory listener answers only `GET` and `HEAD` for
`/.well-known/http-message-signatures-directory`. Its signature covers the
authority of `signature_agent` and the digest of a body crawl-signer builds
from the public key; nothing in the request goes into it. The tag
`http-message-signatures-directory` keeps it from passing as a request
signature, which carries `web-bot-auth`. A copy of the directory under
another authority doesn't verify.

crawl-signer signs the directory at most once per 50 minutes, so requests to
the listener can't make it call the signing key more often. A signature is
valid for an hour; without one, the listener answers `503`.

A Transit key's public part is read from Transit at startup; if its
thumbprint isn't the configured `keyid`, crawl-signer doesn't start.

### Environment properties

| ID | Property | Ensured by |
| --- | --- | --- |
| E1 | Envoy runs with an equivalent of `examples/envoy.yaml`: `ext_proc` with `failure_mode_allow: false` before the forward proxy, `x-crawl-upstream` removed by an early header mutation and by the route, `crawl.internal` listener metadata only on the internal listener, and an access log with the `crawl` metadata | operator |
| E2 | Only crawl-signer can connect to Envoy's internal listener, and only Envoy to crawl-signer's socket | operator, file permissions |
| E3 | The host's firewall stops Envoy from connecting to internal addresses, and stops everything but Envoy from sending from the gateway's published addresses | operator |
| E4 | Only crawl-signer can read the private key, or use the Transit key, and only for signing | operator, OpenBao or Vault policy |
| E5 | Only intended callers can reach the callers' listener | operator |
| E6 | One crawl-signer instance answers for the requests to an origin; each instance paces only what it lets through | operator |

E5 is about cost and accountability, not about the origins: any caller gets
only what G1 to G4 allow.

### What crawl-signer does not defend against

- A replayed signature. Web Bot Auth signatures cover the authority, not the
  path, and carry no nonce, so whoever sees a request can send another to the
  same host until the signature expires, at most 60 seconds later. Origins
  see such requests come from the replayer's address, not the gateway's.
- Load on an origin beyond its `Crawl-delay` (G8). Without one, or above
  what it allows, crawl-signer doesn't limit request rates; the caller's
  scheduler must. Where E6 doesn't hold, n instances let n requests through
  per delay.
- A hostname that resolves to an internal address, where E3 does not hold.
- Anyone who can read the private key or use the Transit key, where E4 does
  not hold. They can sign as the gateway from anywhere.
- A robots.txt change during the cache lifetime described in G3.
