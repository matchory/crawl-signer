# crawl-signer

Go `ext_proc` service that Envoy calls for every request on the crawl gateway.
It enforces static request rules (method, body, port, internal targets, header allowlist).
It runs behind Envoy on crawl gateway nodes.
Test with `go vet ./... && go test -race ./...`.
