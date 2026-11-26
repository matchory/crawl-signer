# Documentation style

This guide is for anyone writing `README.md` or a page in `docs/`, whether you're a person or an agent. The pages
are read on GitHub.

## Voice

Write the way an experienced colleague explains something at a whiteboard: directly, precisely, and without padding.

- **Talk to the reader.** Use "you" and the present tense: "You give crawl-signer a key", not "The user configures
  a key". Contractions are fine.
- **Lead with what the reader wants.** Open a page or section with the outcome or the answer, then the details.
  Nobody needs "This page describes…" first.
- **Give the reason with the fact.** "Keep `x-forwarded-proto` until the route is chosen: Envoy matches no route
  without it" is easier to follow and to remember than the rule alone.
- **Be exact.** Name the command, value, default and condition. When something depends on a condition, state the
  condition instead of writing "usually" or "in most cases". When you quote a number, say where it comes from.
- **Be honest about limits.** Say plainly what crawl-signer doesn't do, what can go wrong, and whom the reader has
  to trust. A reader who is told the limits trusts the rest of the page.
- **Don't sell.** No "seamless", "robust", "powerful", "effortless" or "simply". If a feature is good, the facts
  will show it.

### Tells to avoid

Prose that reads generated loses the reader's trust. Cut these on sight:

- An opener that restates the heading ("In this guide, we will look at…").
- A closing paragraph that summarizes what the reader just read.
- Lists of three adjectives or three parallel clauses where one would do.
- Bold labels on every bullet when the bullets are short sentences anyway.
- "Note that", "It's worth mentioning", "Importantly".
- Linking words that only connect: "Thus", "Hence", "Additionally", "Furthermore".
- Hedges that stand in for a missing fact: "may", "might", "typically", "generally".

## Page types

Each page has one job.

| Type | Where | Its job |
| --- | --- | --- |
| Tutorial | `docs/getting-started.md` | Take a new user from nothing to a signed request, one example, start to finish |
| Guide | `docs/guides/` | Help an operator do one task, including how to tell it worked |
| Reference | `docs/reference/` | List every fact about one interface, so the reader can look it up |
| Explanation | `docs/explanation/` | Say why crawl-signer works the way it does, and what follows from that |

A guide usually starts with what you'll have at the end and what you need first, then the steps, then how to
check the result and where to go next. Skip a section when it would be empty.

A reference page has a short introduction, then one entry per item (a field, a header or a metric): its heading, a
table of facts (type, default), then what it does and its conditions. Reference pages don't give advice; they link
to the guide that does.

Every fact has one home. Other pages link to it instead of repeating it, unless the reader needs it right there to
follow a step.

## Terms

Use one term for one concept.

| Use | Meaning | Not |
| --- | --- | --- |
| caller | A program that sends requests through the gateway | client, crawler, worker |
| origin | A site the gateway sends a request to | target site, upstream, server |
| gateway | Envoy and crawl-signer together | proxy, egress |
| refuse | What crawl-signer does to a request it doesn't let through | reject, deny, block |
| verdict | `ok`, or the reason a request was refused | decision, result |
| signing key | The Ed25519 key that signs requests, local or in Transit | private key, unless it is one |
| product token | The name robots.txt groups match, such as `ExampleBot` | user agent, bot name |
| key directory | The JWKS at `/.well-known/http-message-signatures-directory` | key server, JWKS endpoint |

## Markdown

- One H1 per file.
- Lines of at most 120 characters. Tables are exempt.
- `-` for bullets; number ordered lists `1.`, `2.`, `3.`.
- Give every fenced code block a language: `bash`, `json`, `yaml`, `ini`, `text` or `mermaid`.
- Link between pages with relative `.md` links, anchors included: `[config](../reference/config.md#robots_agent)`.
- Draw diagrams in Mermaid. GitHub renders them.
- Use `> [!WARNING]` only for a risk to data, security or availability, and `> [!NOTE]` for anything else worth
  pulling out. Use them sparingly: a page full of callouts has none.
- Put commands, fields, headers, paths and values in code format.
- Examples use `ExampleBot`, `bot.example.com` and `example.com`, never a real crawler or site.
- Don't write dates or provisional text such as "still to be tested". History belongs in `CHANGELOG.md`.

`SECURITY.md` holds the security guarantees and the environment properties they assume. A test reads its
`### G<n>:` headings, so don't change their format.

## Before and after

| Before | After |
| --- | --- |
| This page describes how crawl-signer decides whether a request is allowed. | A request goes out when the rules, robots.txt and the signing key all say yes. Here's each check, in order. |
| The signer should not be exposed. Thus only Envoy connects. | Give crawl-signer's socket mode `0660` and Envoy's group: any process that can connect can ask for signatures. |
| In most cases, robots.txt is cached for a day. | A robots.txt answer without `Cache-Control: max-age` is used for 24 hours. |
