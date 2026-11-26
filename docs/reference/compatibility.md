# Compatibility

From 1.0, crawl-signer follows [semantic versioning](https://semver.org/spec/v2.0.0.html). You can upgrade within a
major version without changing your configuration, Envoy's configuration, your dashboards or the callers that read
the gateway's refusals. A change that would break what this page lists comes only in a new major version, under
"Changed" or "Removed" in [CHANGELOG.md](../../CHANGELOG.md). Before 1.0, a minor release can break it, and the
changelog says so.

## What stays the same within a major version

| Interface | What holds |
| --- | --- |
| [Configuration](config.md) | Field names, types, defaults and the values each accepts. A new field is optional, and its default keeps today's behaviour |
| [Refusals](envoy-interface.md#a-request-it-refuses) | Each reason keeps its status. `X-Crawl-Gateway-Refusal` names the reason; a `crawl-delay` refusal carries `Retry-After`. A release may add a reason |
| [Header mutations](envoy-interface.md#a-request-it-lets-through) | The headers crawl-signer sets, keeps and removes on a request it lets through |
| [Dynamic metadata](envoy-interface.md#dynamic-metadata) | The namespace `crawl`, its keys and their values. A release may add a key |
| Internal listener | crawl-signer skips robots.txt only for listener metadata `crawl.internal = true` |
| [Metrics](metrics.md) | Names, types and labels. A release may add a metric or a label value |
| Signatures | The covered components, parameters and their order, for each [`signature_agent_form`](config.md#signature_agent_form) |
| Key directory | The path, body and signature that [`directory_listen`](config.md#directory_listen) serves |
| Guarantees | The guarantees G1 to G9 in [SECURITY.md](../../SECURITY.md#security-model). A release may add one or strengthen one, never weaken or remove one |
| Release files | The binary names, `SHA256SUMS` and the build provenance attestation that [Verify a release](../guides/verify-a-release.md) checks |

## What can change in any release

- **A request that used to go through can be refused.** When a release closes a way past the guarantees, it refuses
  those requests at once and lists the change under "Security" in the changelog. crawl-signer fails closed, and
  waiting for a major version would leave the gap open.
- **A request that used to be refused can go through,** when a release fixes a refusal the guarantees didn't call for.
- **Log messages.** Read them, but don't match on their exact text.
- **The Go packages.** Everything under `internal/` is crawl-signer's own code, not a library.
- **The Go toolchain and dependencies** a release is built with. Each release's checksums are its own.

## Supported versions

| | Supported |
| --- | --- |
| Envoy | The minor versions the end-to-end test runs on: 1.39 and 1.40 |
| OpenBao | 2.7, the version the end-to-end test runs |
| Vault | 2.2, the version the end-to-end test runs |
| Platforms | Linux on amd64 and arm64 |
| Web Bot Auth | `Signature-Agent` as [draft-meunier-http-message-signatures-directory-03](https://datatracker.ietf.org/doc/draft-meunier-http-message-signatures-directory/03/) and later drafts' dictionary form; the end-to-end test checks both with Cloudflare's [`web-bot-auth`](https://crates.io/crates/web-bot-auth) 0.8 and the directory with [`http-signature-directory`](https://crates.io/crates/http-signature-directory) 0.8 |

crawl-signer uses only Envoy's `ext_proc` API and Transit's `sign` and key-read endpoints. Other versions aren't
tested.
