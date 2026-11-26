# Verify a release

crawl-signer can sign as your bot, so check that the binary you run is the one this repository's release workflow
built from the tagged source, before you give it your key.

You need the [GitHub CLI](https://cli.github.com/) for the second check.

## Check the checksum

Download the binary and `SHA256SUMS` from the
[releases page](https://github.com/matchory/crawl-signer/releases) into one directory:

```bash
sha256sum --ignore-missing -c SHA256SUMS
```

It prints `OK` for the binary you downloaded. That shows the download is complete, not who built it: `SHA256SUMS`
is not attested. The next check is the one that ties the binary to this repository.

## Check where it was built

Each binary from v0.2.0 on has a build provenance attestation, signed by GitHub for this repository's release
workflow:

```bash
gh attestation verify crawl-signer_0.2.0_linux_amd64 \
  --repo matchory/crawl-signer
```

It prints that the verification succeeded, with the workflow and the tag the binary was built from. A binary
that was changed after the build, or built anywhere else, fails this check.

## Build it yourself

Releases are reproducible. With the Go toolchain `go.mod` names, the same tag gives the same bytes. The `go` line
is only a minimum, so set `GOTOOLCHAIN` to that version, or a newer Go builds different bytes:

```bash
git checkout v0.2.0
GOTOOLCHAIN=go$(awk '/^go / { print $2 }' go.mod) make build GOARCH=amd64 VERSION=v0.2.0
sha256sum bin/crawl-signer_linux_amd64
```

The checksum equals the one in `SHA256SUMS`. The release workflow checks the same: it builds the tag a second time,
on an arm64 runner, and doesn't publish if the checksums differ.
