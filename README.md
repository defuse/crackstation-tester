# crackstation-tester

> **This test suite was written with heavy assistance from AI tools and has not been
> reviewed by a human.** Weigh what it tells you accordingly: a passing run is evidence,
> not proof, and a test asserting the wrong thing passes just as loudly as one asserting
> the right thing.

Black-box integration tests for crackstation.net. They drive a running server over HTTP
and assert on what it actually returns, so they work equally against a dev server and
against production.

```bash
CRACKSTATION_URL=http://localhost:3000 cargo test
```

`CRACKSTATION_URL` is required and must include the scheme. Everything else is derived
from it: the `Origin` header the CSRF checks need, and whether a test that only makes
sense against a real deployment is skipped.

## Running against production

```bash
CRACKSTATION_URL=https://crackstation.net cargo test -- --include-ignored --test-threads=1
```

Four tests are `#[ignore]`d by default because they need a real deployment, and
`--include-ignored` is what runs them:

| test | what only production can prove |
| --- | --- |
| `hsts_exact_value_in_production` | the HSTS header, byte for byte |
| `hsts_present_on_www_in_production` | that `www.` sends it too |
| `http_redirects_to_https_in_production` | the plain-HTTP redirect |
| `invalid_token_rejected_by_google` | that a plausible-but-forged captcha token is relayed to `siteverify` and refused — the only test that exercises the outbound request with the real secret |

`--test-threads=1` is not required but is worth it here: it keeps the suite from opening
~16 concurrent connections to the live site, and it makes the hit-counter tests less
likely to flake (see below).

### What running this does to the live site

Not read-only. The suite makes a few hundred requests, and the server counts every one:

* **Page hits and unique hits move.** Every request to a registered page increments
  `cshits`, and the first from your IP adds a `csnodupes` row. There is no way to opt
  out short of not running it — the counter is unconditional for non-bot user agents.
* **Twelve POSTs submit hashes for cracking.** Real work for the server, harmless
  otherwise. They use the captcha bypass header, so no Google traffic.

None of it is destructive and nothing is written that a visitor could not cause, but the
counters do not go back down.

### Hit-counter tests can flake against a live site

`hit_increments_non_unique_only` and `hit_counter_bot_not_counted` request a page twice
and assert the count went up by exactly one. Real visitors also hit that page. A flake
there means someone else loaded `/legal-privacy.htm` between the two requests, not that
the counter is broken — re-run before investigating.

## Wordlist independence

The suite runs against dev and production unchanged, which constrains what it may
assert. A dev fixture holds a handful of words; production holds about 1.2 billion, so
anything that depends on *which* words exist will pass in one and fail in the other.

Tests therefore assert the server's contract rather than the dictionary's contents. The
cap test checks that exactly 20 rows are shown and that the `more` row's counts satisfy
`hidden == total - 20`, not which twenty words appear. The LM test checks that every
match uppercases to the queried word and that there is more than one spelling, not that
the spellings are `hello`/`Hello`/`HELLO`. These are still exact assertions -- they are
just exact about the right thing.

Two consequences show up in the code:

* **`collapse_repeats`** wraps the row-sequence comparisons. A word in both an
  algorithm's small and huge table is found twice and rendered identically, because the
  type column shows the algorithm name rather than the table label. It is real
  behaviour, matching PHP, and it happens only when the two dictionaries overlap on that
  word -- which they do in production and do not in dev. The full-match case is the
  opposite and is pinned exactly by `word_in_both_dictionaries_no_duplicate`, since the
  early exit there is unconditional.
* **`a_plaintext_that_is_not_utf8_is_shown_as_bytes` skips against production.** It is
  the one test that cannot be written wordlist-independently: it needs a word made of
  invalid UTF-8, and there is no way to locate one in a production list by hash without
  scanning it. It prints a SKIP line rather than passing silently.

## The captcha bypass key

The cracking tests need `secrets/captcha-bypass-key.txt`. The server stores only the
SHA-256 of that key, compiled into the binary, so the same file works against dev and
production. It is gitignored and has never been committed; copy it from a machine that
already has it rather than regenerating, since regenerating means recompiling the server
with the new hash.

Without it, the cracking tests fail rather than skip.

```bash
printf '%s' "$(cat secrets/captcha-bypass-key.txt)" | sha256sum
# must match CAPTCHA_BYPASS_KEY_HASH in crackstation-rust/src/pages/home.rs
```
