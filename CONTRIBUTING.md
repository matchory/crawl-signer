# Contributing

Bug reports, fixes and improvements are welcome. Open an issue first for
larger changes, so we can agree on the approach before you write the code.
Report security issues privately, as described in [SECURITY.md](SECURITY.md).

## Prerequisites

- Go, at the version in [go.mod](go.mod) or newer.
- [golangci-lint](https://golangci-lint.run/), at the version that
  [ci.yml](.github/workflows/ci.yml) pins.
- Docker with Compose, `jq` and `openssl` for the end-to-end test.

## Build and test

```bash
make build   # bin/crawl-signer_linux_<arch>, with the release's flags
make test    # unit tests, with the race detector
make lint    # golangci-lint
make vuln    # govulncheck
make e2e     # end-to-end, with Envoy, OpenBao and a verifying origin in Docker
```

CI runs the same targets. [docs/testing.md](docs/testing.md) describes every
kind of test, and what each one covers.

## Linters

CI runs two linters; run both before opening a pull request.

**Go**: golangci-lint, configured in `.golangci.toml`:

```bash
golangci-lint run        # check
golangci-lint run --fix  # fix what can be fixed automatically
golangci-lint fmt        # format
```

**Everything else** (Markdown, YAML, shell, GitHub Actions):
[super-linter](https://github.com/super-linter/super-linter), configured in
[linter.yml](.github/workflows/linter.yml) with rule files in
`.github/linters/`. To run the most common checks on their own:

```bash
npx -y markdownlint-cli2 --config .github/linters/.markdown-lint.yml "**/*.md"
shellcheck test/e2e/run.sh && shfmt -d test/e2e/run.sh
```

## Code style

- Handle every error. Compare errors with `errors.Is` and `errors.As`, and
  wrap them with `%w`.
- Fail closed: when crawl-signer can't decide on a request, it refuses it.
- Package `rules` imports only the standard library. It holds every static
  rule about a request, so the rules can be read and tested on their own.
- Inject time (`now func() time.Time`) rather than calling `time.Now` in
  code a test needs to control.
- Document exported identifiers. Other comments say why the code is the way
  it is, not what it does.

## Scope

- crawl-signer is for anyone running a crawler. Keep code, docs and tests
  free of assumptions about a particular organisation; examples use
  `ExampleBot`, `bot.example.com` and `example.com`.
- Envoy's behaviour is part of the contract. A change to what crawl-signer
  sends or expects needs the end-to-end test to show it works with Envoy.
- Tests that verify a guarantee in [SECURITY.md](SECURITY.md) name it in a
  `// Guards: G<n>` comment.

## Pull requests

- Keep changes focused, with tests for new behaviour and fixed bugs.
- When behaviour changes, update the documentation. Follow the
  [style guide](docs/STYLE.md).
- Add an entry under `Unreleased` in [CHANGELOG.md](CHANGELOG.md).
- Sign your commits and sign them off (`git commit -S -s`). A pull request
  needs one approval.
- Dependency updates come from Dependabot.

[docs/releasing.md](docs/releasing.md) describes how a release is cut.

By contributing, you agree that your contributions are licensed under the
[Mozilla Public License 2.0](LICENSE).
