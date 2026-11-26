BINARY := crawl-signer
GOOS ?= linux
GOARCH ?= $(shell go env GOARCH)
# The release this build is, such as v0.2.0: crawl-signer logs it at startup.
# Empty for a build that is not a release.
VERSION ?=
# The version ci.yml lints with: another one reads .golangci.toml differently.
GOLANGCI_LINT_VERSION := 2.14.0

.PHONY: build test lint vuln e2e

# The flags of a release build, so a local build has the release's checksum.
build:
	CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) go build -trimpath -buildvcs=false \
		-ldflags "-s -w -buildid= -X main.version=$(VERSION)" \
		-o bin/$(BINARY)_$(GOOS)_$(GOARCH) ./cmd/$(BINARY)

# CI adds report options through the two variables; the tests are the same.
test:
	go tool gotestsum $(GOTESTSUM_FLAGS) -- -race -cover $(TESTFLAGS) ./...

lint:
	@golangci-lint version --short | grep -qx '$(GOLANGCI_LINT_VERSION)' || \
		{ echo "make lint needs golangci-lint $(GOLANGCI_LINT_VERSION), the version ci.yml pins" >&2; exit 1; }
	golangci-lint run

vuln:
	go tool govulncheck ./...

# Needs Docker: see docs/testing.md.
e2e:
	test/e2e/run.sh
