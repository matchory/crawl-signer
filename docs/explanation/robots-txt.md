# robots.txt

crawl-signer checks every request against the origin's robots.txt before it is signed, so a crawler that forgets to,
or gets it wrong, can't fetch a disallowed path under your bot's name. This page explains the choices behind the
check. The numbers are in the [security model](../../SECURITY.md#g3-a-path-robotstxt-disallows-is-not-fetched).

## Which rules apply

robots.txt is per origin: `https://example.com`, `http://example.com` and `https://www.example.com:8443` each have
their own. crawl-signer parses the file with [grobotstxt](https://github.com/jimsmart/grobotstxt), a Go port of
Google's parser, and keeps the rules of one group:

- the group that names your [`robots_agent`](../reference/config.md#robots_agent), matched without case against the
  part of the `User-agent` line before the first character that can't be in a product token, so
  `User-agent: ExampleBot/2.1` names `ExampleBot`;
- otherwise the `*` group.

Of the rules in that group, the longest matching pattern decides, and `Allow` wins a tie, as RFC 9309 specifies.
Patterns support `*` and `$`. Like Google's parser, crawl-signer accepts common misspellings such as `Disalow`, and
reads the first 500 KiB of a file, dropping the line that limit cuts.

`/robots.txt` itself is always allowed, so a crawler can read the file.

## When the file can't be read

RFC 9309 says what an answer means:

| Answer | crawl-signer |
| --- | --- |
| 2xx | Applies the rules |
| 4xx other than 429 | There are no rules: everything is allowed |
| 429, 5xx, timeout, no connection | The origin is unreachable: everything is disallowed |

The last row would make a short outage of an origin's robots.txt stop all crawling of it. So the last good copy
keeps applying while fetches fail, for up to 30 days. A failed fetch is retried after 5 minutes, then 10, 20, 40, and
every hour after that, rather than on every request.

A redirect is followed up to five times, to any host, as RFC 9309 allows; the rules then apply to the original
origin.

## How long a copy is used

A copy is used for its `Cache-Control: max-age`, held between 1 and 24 hours, or for 24 hours without one. RFC 9309
asks crawlers not to use a copy for longer than 24 hours.

A request whose origin has no current copy waits for the fetch. Concurrent requests for the same origin share it. A
request waits at most 10 seconds; after that it is decided by the copy it would have replaced, or refused if there is
none, while the fetch carries on, for up to 30 seconds, and fills the cache for the next request.

## Crawl-delay

`Crawl-delay` isn't in RFC 9309, but sites use it to ask for fewer requests. crawl-signer reads it from the same
group as the rules, as seconds between requests, the way Bing and Yandex do, and caps it at
[`max_crawl_delay_seconds`](../reference/config.md#max_crawl_delay_seconds).

crawl-signer keeps, per origin, the time the next request may go. A request that comes earlier is refused with
`429 crawl-delay` and `Retry-After`, instead of waiting in crawl-signer. Holding requests would be a queue with no
bound, and Envoy gives up on crawl-signer after `message_timeout` anyway, 15 seconds in the example. Your scheduler
already handles `429`, and knows better than crawl-signer which request to send next. A refused request doesn't
take a slot, so retrying early doesn't push the next one back.

The time is kept on the origin's cache entry, in memory, and each instance keeps its own: the
[limitations](limitations.md#rates-and-crawl-delay) say what follows.

## How the fetch leaves

crawl-signer doesn't fetch robots.txt itself. It sends the request to Envoy's
[internal listener](../reference/envoy-interface.md#the-internal-listener), so the fetch is signed and leaves from the
same addresses as your crawl. Origins see one bot, not a crawler and a separate robots.txt fetcher.

## Memory

Rules are kept parsed, not as files, in a least-recently-used cache bounded by
[`robots_cache_bytes`](../reference/config.md#robots_cache_bytes). An origin dropped from the cache is fetched again
when next needed. `crawl_signer_robots_cache_bytes` shows how close the cache is to its bound.
