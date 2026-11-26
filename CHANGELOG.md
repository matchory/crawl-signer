# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-11-26

### Changed

- With Transit, crawl-signer reads the key's public part at startup and
  refuses to start if its thumbprint isn't the configured `keyid`, or if
  Transit doesn't answer. The policy needs `read` on the key as well as
  `update` on `sign`.

- `Signature-Agent` is sent as a structured string, `"https://…"`, covered
  as `"signature-agent"`, by default. Cloudflare's verifier fails the
  dictionary form `sig1="https://…"` with `"signature-agent";key="sig1"`,
  which 0.1.0 sent. `signature_agent_form: "dictionary"` keeps it.
- The configuration changed; crawl-signer refuses to start with a 0.1.0
  file, and with any field it doesn't know:
  - `bao_socket`, `transit_key`, `key_version` and `keyid` move into
    `signing_key`: `{"keyid": …, "transit": {"address": "unix://<bao_socket>",
    "key": <transit_key>, "version": <key_version>}}`.
  - `robots_agent` is required, and must appear in `user_agent`. 0.1.0
    used `MatchoryBot`.
  - `signature_agent` must be an `https://` URL.
  - The Tailscale caller lookup is off unless `tailscale_whois` is `true`.
- The metrics `crawl_signer_transit_sign_total` and
  `crawl_signer_transit_sign_seconds` are now `crawl_signer_sign_total` and
  `crawl_signer_sign_seconds`.
- The dynamic metadata no longer has `key_version`; `keyid` identifies the
  key.
- Release assets are named `crawl-signer_<version>_linux_<arch>`, with
  `SHA256SUMS`, and each binary has a build provenance attestation.

### Added

- A private Ed25519 key as the signing key, from a file, an environment
  variable or the configuration, in the shape of Envoy's `DataSource`, as
  PEM PKCS #8 or JWK. Its `keyid` is computed as its RFC 7638 thumbprint.
- Transit over HTTP(S) as well as a Unix socket, on any mount, with an
  optional token, so OpenBao and Vault work with or without a local proxy.
- `examples/envoy.yaml`, and an end-to-end test that runs it with
  crawl-signer, OpenBao and an origin that verifies every signature.
- Fuzz tests, the security model in `SECURITY.md` with a test per
  guarantee, and documentation.
- The end-to-end test checks signatures and the key directory with
  Cloudflare's `web-bot-auth` and `http-signature-directory` crates, and
  runs against Vault as well as OpenBao. `docs/reference/compatibility.md`
  lists what stays stable and which versions are supported.
- `Crawl-delay` is applied per origin: a request that comes sooner than the
  delay after the last one let through is refused with `429 crawl-delay`
  and `Retry-After`. The delay is capped by the new
  `max_crawl_delay_seconds`, 60 by default. Each instance paces on its own.
- `directory_listen` serves the key directory at
  `/.well-known/http-message-signatures-directory`, signed with the signing
  key as Cloudflare requires, and re-signed before each signature expires.

### Fixed

- crawl-signer's own robots.txt fetches are recognised as internal. Envoy
  sends `xds.listener_metadata` in protobuf text format, which crawl-signer
  didn't read, so the fetches were checked like a caller's request: logged
  as caller `unknown`, and a robots.txt redirected to another path on the
  same origin waited on itself until the fetch timed out.

- An IPv6 literal with a zone, such as `[2001:db8::1%eth0]`, is refused as
  `target`. 0.1.0 accepted it in the rules and refused it only when
  signing.
- `x-forwarded-proto` is kept until the route is chosen. Without it, Envoy
  matched no route once crawl-signer cleared the route cache, and every
  allowed request was answered with a 404.

## [0.1.0] - 2026-11-25

### Added

- An Envoy `ext_proc` server that refuses requests other than `GET` and
  `HEAD` without a body, to the scheme's default port, for a hostname or a
  public address.
- robots.txt (RFC 9309) for each origin, fetched through Envoy's internal
  listener and cached in memory.
- Web Bot Auth signatures with an OpenBao Transit key behind a local proxy.
- A header allowlist, and the gateway's own `User-Agent` and `From`.
- The caller's Tailscale node in Envoy's dynamic metadata, and Prometheus
  metrics.

[Unreleased]: https://github.com/matchory/crawl-signer/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/matchory/crawl-signer/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/matchory/crawl-signer/releases/tag/v0.1.0
