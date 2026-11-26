// Command origin is the website in the end-to-end test. It serves robots.txt
// files that differ by host and answers every other request with what it
// received, including whether the request's Web Bot Auth signature verifies.
//
// It verifies signatures with its own code, not crawl-signer's, the way a
// site that checks them would: the test then shows that crawl-signer's
// signatures verify, not that its code agrees with itself.
package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const robots = `User-agent: *
Disallow: /

User-agent: ExampleBot
Disallow: /private
Allow: /
`

// The parameters crawl-signer must sign with, in its order. The agent
// component has a key parameter in the dictionary form only.
var input = regexp.MustCompile(
	`^sig1=\("@authority" ("signature-agent"(?:;key="sig1")?)\);created=(\d+);expires=(\d+);keyid="([^"]+)";alg="ed25519";tag="web-bot-auth"$`,
)

type answer struct {
	Host      string              `json:"host"`
	Path      string              `json:"path"`
	TLS       bool                `json:"tls"`
	Headers   map[string][]string `json:"headers"`
	Signature string              `json:"signature"`
	// AgentForm is "string" or "dictionary": the Signature-Agent form the
	// request used.
	AgentForm string `json:"agent_form"`
}

func main() {
	pubFile := flag.String(
		"public-key",
		"",
		"file with the base64 Ed25519 public key signatures must verify with",
	)
	certFile := flag.String("cert", "", "TLS certificate")
	keyFile := flag.String("key", "", "TLS key")
	directory := flag.String(
		"directory",
		"",
		"URL that bot.example.com, the bot's own site, forwards requests to",
	)
	thumbprint := flag.String(
		"thumbprint",
		"",
		"print the JWK thumbprint of this base64 Ed25519 public key and exit",
	)
	flag.Parse()

	if *thumbprint != "" {
		pub, err := base64.StdEncoding.DecodeString(*thumbprint)
		if err != nil {
			log.Fatal(err)
		}

		fmt.Println(jwkThumbprint(pub))

		return
	}

	dir, err := url.Parse(*directory)
	if err != nil {
		log.Fatal(err)
	}

	h := handler(httputil.NewSingleHostReverseProxy(dir), func() ed25519.PublicKey {
		b, err := os.ReadFile(*pubFile)
		if err != nil {
			return nil
		}

		pub, _ := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))

		return pub
	})

	errc := make(chan error, 2)

	go func() {
		srv := &http.Server{Addr: ":80", Handler: h, ReadHeaderTimeout: 5 * time.Second}
		errc <- srv.ListenAndServe()
	}()

	go func() {
		srv := &http.Server{Addr: ":443", Handler: h, ReadHeaderTimeout: 5 * time.Second}
		errc <- srv.ListenAndServeTLS(*certFile, *keyFile)
	}()

	log.Fatal(<-errc)
}

// handler reads the public key per request, so the test can start the
// origin before it knows the key. bot.example.com is the bot's own site,
// which forwards to crawl-signer's key directory, as an operator's would.
func handler(site http.Handler, publicKey func() ed25519.PublicKey) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, _ := strings.Cut(r.Host, ":")

		if host == "bot.example.com" {
			site.ServeHTTP(w, r)

			return
		}

		if r.URL.Path == "/robots.txt" {
			switch host {
			case "norobots.test":
				http.NotFound(w, r)
			case "broken.test":
				http.Error(w, "down", http.StatusServiceUnavailable)
			case "slow.test":
				_, _ = w.Write([]byte("User-agent: *\nCrawl-delay: 30\n"))
			case "moved.test":
				http.Redirect(w, r, "https://origin.test/robots.txt", http.StatusMovedPermanently)
			default:
				_, _ = w.Write([]byte(robots))
			}

			return
		}

		a := answer{Host: r.Host, Path: r.URL.RequestURI(), TLS: r.TLS != nil, Headers: r.Header}

		a.Signature = "valid"
		a.AgentForm = "string"

		if strings.HasPrefix(r.Header.Get("Signature-Agent"), "sig1=") {
			a.AgentForm = "dictionary"
		}

		if err := verify(r, publicKey()); err != nil {
			a.Signature = err.Error()
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(a)
	})
}

// verify checks the request's signature as RFC 9421 and the Web Bot Auth
// draft describe it.
func verify(r *http.Request, pub ed25519.PublicKey) error {
	if len(pub) != ed25519.PublicKeySize {
		return errors.New("no public key")
	}

	agent := r.Header.Get("Signature-Agent")
	sigInput := r.Header.Get("Signature-Input")
	sigHeader := r.Header.Get("Signature")

	if agent == "" || sigInput == "" || sigHeader == "" {
		return errors.New("missing signature headers")
	}

	m := input.FindStringSubmatch(sigInput)
	if m == nil {
		return fmt.Errorf("unexpected Signature-Input %q", sigInput)
	}

	component := m[1]
	created, _ := strconv.ParseInt(m[2], 10, 64)
	expires, _ := strconv.ParseInt(m[3], 10, 64)

	now := time.Now().Unix()
	if created > now+5 || now >= expires || expires-created > 24*3600 {
		return fmt.Errorf(
			"outside its validity: created %d, expires %d, now %d",
			created,
			expires,
			now,
		)
	}

	if m[4] != jwkThumbprint(pub) {
		return fmt.Errorf("keyid %s is not the key's thumbprint", m[4])
	}

	agentValue, err := coveredAgent(agent, component)
	if err != nil {
		return err
	}

	params := strings.TrimPrefix(sigInput, "sig1=")
	base := `"@authority": ` + strings.ToLower(r.Host) + "\n" +
		component + ": " + agentValue + "\n" +
		`"@signature-params": ` + params

	if !strings.HasPrefix(sigHeader, "sig1=:") || !strings.HasSuffix(sigHeader, ":") {
		return fmt.Errorf("unexpected Signature %q", sigHeader)
	}

	sig, err := base64.StdEncoding.DecodeString(sigHeader[len("sig1=:") : len(sigHeader)-1])
	if err != nil {
		return fmt.Errorf("signature: %w", err)
	}

	if !ed25519.Verify(pub, []byte(base), sig) {
		return errors.New("does not verify")
	}

	return nil
}

func jwkThumbprint(pub []byte) string {
	sum := sha256.Sum256(
		[]byte(
			`{"crv":"Ed25519","kty":"OKP","x":"` + base64.RawURLEncoding.EncodeToString(pub) + `"}`,
		),
	)

	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// coveredAgent returns the value of Signature-Agent the signature covers:
// either the whole header is an sf-string, or, in the dictionary form, the
// member sig1 is.
func coveredAgent(header, component string) (string, error) {
	v := header
	if strings.HasSuffix(component, `;key="sig1"`) {
		member, ok := strings.CutPrefix(header, "sig1=")
		if !ok {
			return "", fmt.Errorf("signed as a dictionary, but Signature-Agent is %q", header)
		}

		v = member
	}

	if !strings.HasPrefix(v, `"https://`) || !strings.HasSuffix(v, `"`) {
		return "", fmt.Errorf("unexpected Signature-Agent %q", header)
	}

	return v, nil
}
