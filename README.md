# crawl-signer

Go `ext_proc` service that Envoy calls for every request on the crawl gateway.
It enforces static request rules (method, body, port, internal targets, header allowlist) and robots.txt, and signs what it allows through OpenBao Transit.
It runs behind Envoy on crawl gateway nodes.
One header outside the allowlist stays: `X-Forwarded-Proto`, because Envoy matches no route without it, so Envoy's route config must strip it (`request_headers_to_remove`).
Test with `go vet ./... && go test -race ./...`.
