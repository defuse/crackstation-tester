# crackstation-tester

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
