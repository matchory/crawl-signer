# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

An Envoy `ext_proc` server for a crawl gateway: Envoy asks it about every request; it enforces static rules and
robots.txt and signs what it lets through with Web Bot Auth (RFC 9421, Ed25519). It is public, generic software:
nothing in code, docs or tests may name a particular organisation, crawler or deployment.

Read [SECURITY.md](SECURITY.md) before changing what is refused, signed or forwarded.

## Commands

```bash
make test    # unit tests, race detector on (gotestsum, pinned in go.mod's tool block)
make lint    # golangci-lint, the version ci.yml pins
make vuln    # govulncheck
make build   # release-flag build into bin/crawl-signer_linux_<arch>
make e2e     # Envoy + crawl-signer + OpenBao + verifying origin in Docker; Linux or macOS
```

```bash
go test ./internal/robots/ -run TestTTL                 # one package, one group
go test -v -run TestEveryGuaranteeIsGuarded .           # which tests guard each G<n>
go test -run='^$' -fuzz='^FuzzCheck$' -fuzztime=30s ./internal/rules/
golangci-lint fmt                                       # format (gofumpt, gci, golines)
ENVOY_VERSION=1.39.6 test/e2e/run.sh                    # e2e against another Envoy
```

Run the tests a change touches while working. CI runs everything, including super-linter for Markdown, YAML, shell
and Actions (`shellcheck`, `shfmt`, `actionlint`, `zizmor` locally).

## Layout

| Package | Holds |
| --- | --- |
| `internal/rules` | Static request rules and the header allowlist; standard library only |
| `internal/robots` | robots.txt parsing (grobotstxt), the per-origin cache, and the fetcher through Envoy's internal listener |
| `internal/sign` | Signature base, the per-authority signature cache, and the `Backend`s: `LocalKey` and `Transit` |
| `internal/directory` | The signed key directory `directory_listen` serves |
| `internal/extproc` | The ext_proc server: one verdict per request, header mutation, dynamic metadata |
| `internal/whois` | Optional Tailscale caller lookup |
| `internal/metrics` | Prometheus metrics, as decorators around the fetcher and the backend |
| `internal/config` | The JSON config; `DataSource` mirrors Envoy's (filename / environment_variable / inline_string) |
| `cmd/crawl-signer` | Wiring; `signingBackend` picks the key and resolves the keyid |
| `test/e2e` | `run.sh`, `compose.yaml`, and `origin/`, which verifies signatures with its own code |

## Request flow

`extproc.Server.requestHeaders`: caller (listener metadata `crawl.internal`, optional whois) → scheme
(`X-Crawl-Scheme`) → `rules.Check` → `robots.Check` (skipped for internal) → `signer.Headers` → `mutation` (set
identity, remove everything not allowlisted) with `ClearRouteCache`. Any refusal is an `ImmediateResponse` with
`x-crawl-gateway-refusal: <reason>`; the reason is also the `verdict` metadata and metric label.

## Rules that are easy to break

- Fail closed. Anything crawl-signer can't decide on is refused.
- Keep `host` and `x-forwarded-proto` out of `RemoveHeaders`: Envoy matches no route without `x-forwarded-proto`
  after the route cache is cleared. The end-to-end test catches this; unit tests don't.
- Two authority forms (`internal/sign/base.go`): `CanonicalAuthority` keys the caches; `SignatureAuthority` is
  `@authority` and keeps a trailing dot, because Envoy forwards it as received.
- `Signature-Agent` defaults to the structured-string form (`"https://…"`, no `key` parameter): Cloudflare fails the
  dictionary form. `signature_agent_form: dictionary` is the later-draft form.
- A local key's keyid is its RFC 7638 thumbprint; a configured keyid that differs stops startup.
- robots.txt fetches and whois queries run on their own contexts and timeouts, so a caller giving up never poisons a
  cache. Time is injected (`now func() time.Time`); timeouts tests shorten are package variables.
- A test that proves a guarantee carries `// Guards: G<n>` (Go) or `# Guards: G<n>` before a `check` block (end-to-end).
  `security_test.go` fails if a guarantee has none or a marker marks no test.
- `examples/envoy.yaml` is what the end-to-end test runs. Change Envoy behaviour there, then in the docs.

## Standards

- Code passes `.golangci.toml`. A `nolint` names its linter and gives a reason.
- Exported identifiers have doc comments. Other comments say why, never what.
- `README.md` and `docs/` follow [docs/STYLE.md](docs/STYLE.md). Examples use `ExampleBot`, `bot.example.com`,
  `example.com`.
- A change in behaviour gets a line under `Unreleased` in `CHANGELOG.md`; release notes come from it.
- Images in `test/e2e/run.sh` are pinned by digest; a new Envoy or OpenBao version needs its digest added.
