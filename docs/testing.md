# Testing

crawl-signer has four kinds of test. Each answers a different question, and CI runs all of them.

| Kind | Where | Runs | Answers |
| --- | --- | --- | --- |
| Unit | `*_test.go` in each package | `make test`, on every push | Does each rule, cache and conversion behave as specified? |
| Fuzz | `fuzz_test.go` in `rules`, `sign`, `robots` and `extproc` | weekly, 10 minutes per target | Does any input make crawl-signer accept what it must refuse, sign what it mustn't, or crash? |
| Guarantee check | `security_test.go` | `make test`, on every push | Does every guarantee in `SECURITY.md` have a test that proves it? |
| End-to-end | `test/e2e/run.sh` | `make e2e`, on every pull request | Do Envoy, crawl-signer and a signing key together send what a verifier accepts, and refuse what they should? |

## Unit tests

```bash
make test                                   # everything, with the race detector
go test ./internal/robots/ -run TestTTL     # one package, one group
```

Time is passed in as a function, so cache tests move a fake clock instead of sleeping. Envoy, the signing key,
`tailscaled` and origins are replaced by small fakes behind the interfaces `extproc`, `sign`, `robots` and `whois`
define; Transit and the robots.txt fetcher are tested against HTTP servers on Unix sockets.

## Fuzz tests

```bash
go test -run='^$' -fuzz='^FuzzCheck$' -fuzztime=30s ./internal/rules/
go test -run='^$' -fuzz='^FuzzSignatureAuthority$' -fuzztime=30s ./internal/sign/
go test -run='^$' -fuzz='^FuzzCanonicalAuthority$' -fuzztime=30s ./internal/sign/
go test -run='^$' -fuzz='^FuzzParse$' -fuzztime=30s ./internal/robots/
go test -run='^$' -fuzz='^FuzzDisallowAll$' -fuzztime=30s ./internal/robots/
go test -run='^$' -fuzz='^FuzzMaxAge$' -fuzztime=30s ./internal/robots/
go test -run='^$' -fuzz='^FuzzHeaders$' -fuzztime=30s ./internal/extproc/
```

Each target checks a property against something other than the code under test: `FuzzCheck` against `net/netip`'s
own classification of addresses, `FuzzSignatureAuthority` that the signature base keeps exactly three lines,
`FuzzHeaders` that no header outside the allowlist survives.

A failing input is saved under the package's `testdata/fuzz/`; commit it with the fix, and it becomes a regression
test. The weekly run keeps its corpus in the Actions cache from one run to the next, and opens an issue when it finds a
failing input.

## Security model

`SECURITY.md` publishes the guarantees as headings of the form `### G1: …`. A test that proves one says so in its doc
comment:

```go
// Guards: G4
func FuzzHeaders(f *testing.F) {
```

The end-to-end script marks its sections the same way, with `# Guards: G3` followed by lines that run a `check`
before the next empty line. `TestEveryGuaranteeIsGuarded` fails when a published guarantee has no guard, when a guard
names a guarantee that isn't published, and when a marker marks no test. A marker says which guarantee a test is
about, not that the test covers all of it. Run it with `-v` to list the files guarding each guarantee:

```bash
go test -v -run TestEveryGuaranteeIsGuarded .
```

## End-to-end test

```bash
make e2e
```

It needs Docker with Compose, Go, `jq` and `openssl`, and runs on Linux and macOS. It builds crawl-signer and the test
origin for Docker's architecture, then starts, from `test/e2e/compose.yaml`:

| Container | Role |
| --- | --- |
| `envoy` | Envoy with `examples/envoy.yaml`, unchanged, trusting a CA the test creates |
| `signer` | crawl-signer |
| `origin` | `test/e2e/origin`: one website under four names with different robots.txt answers, which verifies every request's signature with its own code and answers with what it received |
| `openbao` | OpenBao in dev mode, for the Transit key |
| `client` | curl, in Envoy's network namespace, as a caller on the gateway host |

It runs twice: with a private key file and the `string` Signature-Agent form, then with a Transit key, a token from
the environment and the `dictionary` form. Each run checks that an allowed request arrives over TLS with a
signature that verifies, the configured identity and only allowlisted headers; that a caller can't replace the
signature, the `User-Agent` or the scheme; that robots.txt is applied through a 404, a 503 and a redirect; that the
rules refuse a POST, a body, another port and internal addresses; that Envoy's access log and the metrics record the
verdicts; and that nothing is sent once crawl-signer stops.

`ENVOY_VERSION` and `OPENBAO_VERSION` choose the versions, and the script records the image digest of each: a new
version needs its digest added to `run.sh`. CI runs the newest release of Envoy's two latest minors.
`E2E_PAUSE=600` keeps the containers running for ten minutes after a failure.

## What no test covers

- A real verifier. The test origin implements the checks Cloudflare documents, but it isn't Cloudflare.
- The key directory, which crawl-signer doesn't serve.
- Throughput and latency: no test measures them.
- The host firewall and systemd units in [Deploy with Envoy](guides/deploy-with-envoy.md). The nftables table is
  syntax-checked by hand, not in CI.
