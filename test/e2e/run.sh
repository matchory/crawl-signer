#!/usr/bin/env bash
# End-to-end test: Envoy with examples/envoy.yaml, crawl-signer, an origin
# that verifies signatures with its own code, and OpenBao for Transit. Runs
# once with a private key file and once with a Transit key.
#
# Needs Docker with Compose, jq, openssl and Go.
# ENVOY_VERSION and OPENBAO_VERSION choose the versions; docs/testing.md
# lists the rest.
set -euo pipefail

cd "$(dirname "$0")"
root=$(cd ../.. && pwd)

ENVOY_VERSION=${ENVOY_VERSION:-1.40.2}
OPENBAO_VERSION=${OPENBAO_VERSION:-2.7.3}

# Images by digest: a tag can be moved, a digest can't. A new version needs
# its digest added here.
declare -A envoy_digests=(
  ["1.40.2"]=sha256:8de97e654644827d62afdbf7e1d3dc9fee01a8690d410dd1c63a30dc6b6cecbb
  ["1.39.6"]=sha256:1fde8efee875e4e4f6a39a90fe49d9338e1caacce5762034ef9fb4bbb9ad6aed
)
declare -A openbao_digests=(
  ["2.7.3"]=sha256:ba4b133eb9586630024e71a617e66f37f29cc3534cdd46a6233e098ceded8dc9
)
for pair in "envoy ${ENVOY_VERSION} ${envoy_digests[${ENVOY_VERSION}]:-}" \
  "openbao ${OPENBAO_VERSION} ${openbao_digests[${OPENBAO_VERSION}]:-}"; do
  read -r name version digest <<<"${pair}"
  if [[ -z ${digest} ]]; then
    echo "no digest recorded for ${name} ${version}: add it to $0" >&2
    exit 1
  fi
done

export ENVOY_IMAGE="envoyproxy/envoy:v${ENVOY_VERSION}@${envoy_digests[${ENVOY_VERSION}]}"
export OPENBAO_IMAGE="openbao/openbao:${OPENBAO_VERSION}@${openbao_digests[${OPENBAO_VERSION}]}"
export ALPINE_IMAGE="alpine:3.22@sha256:49340b346798875b5592e5d420241f2f9cfba5f47e62ebb1446a1b34734e898f"
export CURL_IMAGE="curlimages/curl:8.17.0@sha256:935d9100e9ba842cdb060de42472c7ca90cfe9a7c96e4dacb55e79e560b3ff40"

WORK=$(mktemp -d)
export WORK
chmod 755 "${WORK}"

compose() { docker compose --progress quiet --file compose.yaml "$@"; }

cleanup() {
  status=$?
  if [[ ${status} -ne 0 ]]; then
    compose logs --no-color --tail 30 || true
    if [[ -n ${E2E_PAUSE:-} ]]; then
      echo "pausing ${E2E_PAUSE}s for inspection (WORK=${WORK})"
      sleep "${E2E_PAUSE}"
    fi
  fi
  compose down --volumes --timeout 1 >/dev/null 2>&1 || true
  rm -rf "${WORK}"
  exit "${status}"
}
trap cleanup EXIT

failed=0

# check NAME COMMAND...: runs COMMAND and records whether it succeeded.
check() {
  local name=$1
  shift
  if "$@"; then
    echo "  ok    ${name}"
  else
    echo "  FAIL  ${name}"
    failed=1
  fi
}

# fetch URL [CURL ARGS...]: sends a request through Envoy as a caller.
# Sets status, refusal (the x-crawl-gateway-refusal header) and body.
fetch() {
  local out
  out=$(compose exec -T client curl -sS --max-time 20 --proxy http://127.0.0.1:3128 \
    -w '\n%{http_code} %header{x-crawl-gateway-refusal}' "$@" || true)
  body=$(sed '$d' <<<"${out}")
  read -r status refusal <<<"$(tail -n 1 <<<"${out}")"
  refusal=${refusal:-}
}

is() { [[ $1 == "$2" ]]; }
body_is() { jq -e "$1" <<<"${body}" >/dev/null 2>&1; }
refused() { is "${status}" "$1" && is "${refusal}" "$2"; }
# logged FILTER: Envoy's access log has a line FILTER selects. Envoy writes
# the log every 10 seconds, so this waits up to 15.
logged() {
  for _ in $(seq 30); do
    compose logs --no-color --no-log-prefix envoy | grep '^{' | jq -e "$1" 2>/dev/null | grep -q . && return
    sleep 0.5
  done
  return 1
}

build() {
  local arch
  case $(docker info --format '{{.Architecture}}') in
  x86_64 | amd64) arch=amd64 ;;
  aarch64 | arm64) arch=arm64 ;;
  *) echo "unsupported Docker architecture" >&2 && exit 1 ;;
  esac
  (cd "${root}" && make build GOARCH="${arch}" >/dev/null)
  cp "${root}/bin/crawl-signer_linux_${arch}" "${WORK}/crawl-signer"
  (cd "${root}" && CGO_ENABLED=0 GOOS=linux GOARCH="${arch}" go build -o "${WORK}/origin" ./test/e2e/origin)
}

certificates() {
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 \
    -subj /CN=e2e-ca -keyout "${WORK}/ca.key" -out "${WORK}/ca.crt" 2>/dev/null
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj /CN=origin.test \
    -keyout "${WORK}/origin.key" -out "${WORK}/origin.csr" 2>/dev/null
  openssl x509 -req -in "${WORK}/origin.csr" -CA "${WORK}/ca.crt" -CAkey "${WORK}/ca.key" \
    -CAcreateserial -days 1 -out "${WORK}/origin.crt" \
    -extfile <(printf 'subjectAltName=DNS:origin.test,DNS:norobots.test,DNS:broken.test,DNS:moved.test') 2>/dev/null
  chmod 644 "${WORK}"/*.crt "${WORK}"/*.key
}

# signer_config SIGNING_KEY_JSON FORM: writes crawl-signer's configuration.
signer_config() {
  cat >"${WORK}/signer.json" <<EOF
{
  "listen": "/run/crawl-signer/grpc.sock",
  "envoy_socket": "/run/envoy/internal.sock",
  "metrics_listen": "0.0.0.0:9100",
  "user_agent": "Mozilla/5.0 (compatible; ExampleBot/1.0; +https://bot.example.com)",
  "from": "bot@example.com",
  "signature_agent": "https://bot.example.com",
  "signature_agent_form": "$2",
  "robots_agent": "ExampleBot",
  "robots_cache_bytes": 1048576,
  "signing_key": $1
}
EOF
}

# setup_file: a private key in a file, as a secret manager would deliver it,
# and the Signature-Agent form Cloudflare verifies.
setup_file() {
  openssl genpkey -algorithm ed25519 -out "${WORK}/signing.pem"
  chmod 644 "${WORK}/signing.pem"
  openssl pkey -in "${WORK}/signing.pem" -pubout -outform DER | tail -c 32 | base64 >"${WORK}/public-key"
  signer_config '{"private_key": {"filename": "/e2e/signing.pem"}}' string
}

# setup_transit: a Transit key in OpenBao; crawl-signer reads the token
# from its environment. The dictionary form of later Web Bot Auth drafts.
setup_transit() {
  compose up --detach --wait openbao >/dev/null
  for _ in $(seq 50); do
    compose exec -T openbao bao status >/dev/null 2>&1 && break
    sleep 0.2
  done
  compose exec -T openbao bao secrets enable transit >/dev/null
  compose exec -T openbao bao write -f transit/keys/web-bot-auth type=ed25519 >/dev/null
  compose exec -T openbao bao read -format=json transit/keys/web-bot-auth |
    jq -r '.data.keys["1"].public_key' >"${WORK}/public-key"
  local keyid
  keyid=$(cd "${root}" && go run ./test/e2e/origin -thumbprint "$(cat "${WORK}/public-key")")
  signer_config "{\"keyid\": \"${keyid}\", \"transit\": {\"address\": \"http://openbao:8200\",
    \"key\": \"web-bot-auth\", \"version\": 1, \"token\": {\"environment_variable\": \"BAO_TOKEN\"}}}" dictionary
}

start() {
  compose up --detach origin signer envoy client >/dev/null
  for _ in $(seq 100); do
    fetch http://origin.test/
    [[ ${status} != 000 ]] && return
    sleep 0.2
  done
  echo "Envoy did not answer" >&2
  exit 1
}

# run_checks FORM: the checks, for a signer that sends Signature-Agent in FORM.
run_checks() {
  # Guards: G1, G3
  fetch http://origin.test/page -H 'Accept: text/html'
  check "an allowed request reaches the origin over https" is "${status}" 200
  check "its signature verifies with the public key" body_is '.signature == "valid"'
  check "Signature-Agent has the ${1} form" body_is ".agent_form == \"${1}\""
  check "it went over TLS" body_is '.tls == true'
  check "it carries the configured User-Agent" \
    body_is '.headers["User-Agent"] == ["Mozilla/5.0 (compatible; ExampleBot/1.0; +https://bot.example.com)"]'
  check "it carries From" body_is '.headers["From"] == ["bot@example.com"]'
  check "it keeps an allowlisted header" body_is '.headers["Accept"] == ["text/html"]'

  # Guards: G4
  fetch http://origin.test/page -H 'User-Agent: spoof' -H 'Cookie: a=b' -H 'Authorization: Bearer x' \
    -H 'Signature: sig1=:AAAA:' -H 'X-Forwarded-For: 192.0.2.1' -H 'X-Crawl-Upstream: http'
  check "a caller's User-Agent is replaced" body_is '.headers["User-Agent"] | length == 1 and (.[0] | test("ExampleBot"))'
  check "a caller's own Signature is replaced, and verifies" body_is '.signature == "valid"'
  check "Cookie and Authorization are removed" body_is '.headers | has("Cookie") or has("Authorization") | not'
  check "Envoy's and crawl-signer's own headers are removed" \
    body_is '.headers | keys | map(ascii_downcase) | map(select(startswith("x-"))) == []'
  check "a caller can't choose plain http with X-Crawl-Upstream" body_is '.tls == true'

  # Guards: G1
  fetch http://origin.test/page -H 'X-Crawl-Scheme: http'
  check "X-Crawl-Scheme: http reaches the origin over plain http" body_is '.tls == false and .signature == "valid"'

  # Guards: G3
  fetch http://origin.test/private
  check "a path robots.txt disallows is refused" refused 403 robots
  fetch http://norobots.test/private
  check "a 404 robots.txt allows everything" is "${status}" 200
  fetch http://broken.test/page
  check "a 5xx robots.txt refuses everything" refused 403 robots-unavailable
  fetch http://moved.test/private
  check "a redirected robots.txt is followed" refused 403 robots

  # Guards: G2
  fetch http://origin.test/page -X POST
  check "POST is refused" refused 405 method
  fetch http://origin.test/page -H 'Content-Length: 4' --data-binary abcd -X GET
  check "a request body is refused" refused 413 body
  fetch http://origin.test:8443/page
  check "a port other than the scheme's is refused" refused 403 port
  fetch http://127.0.0.1/page
  check "a loopback address is refused" refused 403 target
  fetch "http://[::ffff:10.0.0.1]/page"
  check "an IPv4-mapped private address is refused" refused 403 target

  # Guards: G6
  check "the access log records the verdict and the robots.txt outcome" logged \
    'select(.path == "/private" and .verdict == "robots" and .robots == "disallowed")'
  check "metrics count verdicts" bash -c \
    'docker compose --file compose.yaml exec -T client curl -sS http://signer:9100/metrics |
      grep -q "^crawl_signer_requests_total{verdict=\"robots\"} [1-9]"'

  # Guards: G1
  compose stop signer >/dev/null
  fetch http://origin.test/page
  check "nothing is sent while crawl-signer is down" bash -c "[[ ${status} =~ ^5 ]]"
}

build
certificates
for variant in file:string transit:dictionary; do
  key=${variant%:*} form=${variant#*:}
  echo "Envoy ${ENVOY_VERSION}, signing key: ${key}, Signature-Agent: ${form}"
  "setup_${key}"
  start
  run_checks "${form}"
  compose down --volumes --timeout 1 >/dev/null 2>&1
done

if [[ ${failed} -ne 0 ]]; then
  echo "end-to-end test failed" >&2
  exit 1
fi
echo "end-to-end test passed"
