//! Hash cracking tests
//!
//! Tests for the hash cracking form and results.
//! All POST tests use the X-Captcha-Bypass header to skip reCAPTCHA.
//!
//! Result assertions compare the *entire* parsed results table against an exact
//! expected list with `assert_eq!`. That catches extra rows, missing rows, wrong
//! ordering, and wrong row colors — a substring search over the page body catches
//! none of those, and can pass on text that came from the color-code legend or the
//! echoed-back textarea rather than from a result row.

mod common;

/// md5("monkey"). A near-miss row shows the digest the word really produces, so this
/// is what the hash column holds whenever a query only matched monkey's md5 prefix.
const MD5_MONKEY: &str = "d0763edaa9d9bd2a9516280e9044d885";

use reqwest::header::{CONTENT_TYPE, ORIGIN};

use common::{
    assert_body_contains, assert_body_does_not_contain, assert_success, captcha_bypass_secret,
    client, collapse_repeats, is_production_url, origin, parse_results, results,
    submitted_hashes_textarea, truncation_counts, url, ResultRow, RESULT_LIMIT,
};

// What is and is not verifiable against a dev server, since it decides which captcha
// tests can run anywhere:
//
// `dev/dotenv-example` sets `RECAPTCHA_SECRET_KEY` to Google's test secret, which
// validates any token it is *given*. But the server no longer asks Google about every
// token: an absent or implausibly long one is rejected locally, before any outbound
// request. So a captcha-less POST is refused identically in dev and in production, and
// the two tests below run everywhere.
//
// Still not verifiable in dev: rejection of a token that is present and plausibly
// sized but wrong. The test secret accepts those, so only a server holding a real
// secret can refuse one, and only by asking Google. `invalid_token_rejected_by_google`
// covers it, guarded by `require_captcha_enforcement`.

/// Guard for tests whose verdict can only come from Google.
///
/// `dev/dotenv-example` sets `RECAPTCHA_SECRET_KEY` to Google's published test secret,
/// which validates any token it is *given*. Absent and oversized tokens never reach it
/// -- the server refuses those locally -- so those rejections are testable anywhere.
/// A token that is present, plausibly sized and simply wrong is not: the test secret
/// accepts it, so asserting its rejection against a dev server would verify nothing.
///
/// Such tests are marked `#[ignore]`, so a default run reports them as ignored rather
/// than counting them as passes. Run them with:
///
/// ```text
/// CRACKSTATION_URL=https://crackstation.net cargo test -- --include-ignored
/// ```
///
/// If one is force-included against a server that cannot reject, fail loudly rather
/// than reporting a pass that verified nothing.
fn require_captcha_enforcement(test_name: &str) {
    assert!(
        is_production_url(),
        "{} needs a server holding a real reCAPTCHA secret, but CRACKSTATION_URL points at a \
         dev server using Google's always-pass test secret — it accepts any token that reaches \
         it, so this test would verify nothing. Point CRACKSTATION_URL at production.",
        test_name
    );
}

/// Whether the target is the dev server, whose `dev/cracking` fixture is the only place
/// a specific crafted word is known to exist.
///
/// Used by the one test that cannot be written wordlist-independently: rendering a
/// non-UTF-8 plaintext needs a word made of invalid UTF-8, and there is no way to find
/// one in a 1.2-billion-word production list without scanning it. Every other test here
/// asserts a property of the server rather than the contents of a dictionary, and runs
/// against both.
fn dev_fixture_only(test_name: &str) -> bool {
    if is_production_url() {
        eprintln!(
            "SKIP {}: needs the crafted non-UTF-8 entry in dev/cracking, which exists in \
             no production wordlist that can be located by hash.",
            test_name
        );
        return false;
    }
    true
}

/// A token shaped like a real reCAPTCHA v2 response but not issued by Google.
///
/// Length and alphabet matter: the server refuses an absent or oversized token locally,
/// without an outbound request, and such a refusal would produce the same page as a
/// genuine rejection. Staying inside the range the server relays is what makes the
/// verdict Google's rather than the server's own.
fn plausible_but_invalid_token() -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    (0..800)
        .map(|i| ALPHABET[(i * 7 + 13) % ALPHABET.len()] as char)
        .collect()
}

/// Extract the red error message shown above the results, if any.
fn extract_error(body: &str) -> Option<String> {
    let marker = "<p style=\"color: red;\">";
    let start = body.find(marker)? + marker.len();
    let region = &body[start..];
    let open = region.find("<b>").expect("error paragraph has no <b> tag") + "<b>".len();
    let close = region[open..]
        .find("</b>")
        .expect("error paragraph has no closing </b>");
    Some(region[open..open + close].trim().to_string())
}

/// POST hashes with the captcha bypass header and return the response body.
async fn crack(hashes: &str) -> String {
    let resp = client()
        .post(url("/"))
        .header(ORIGIN, origin())
        .header("X-Captcha-Bypass", captcha_bypass_secret())
        .form(&[("hashes", hashes)])
        .send()
        .await
        .expect("request failed");
    assert_success(&resp, "crack request");
    resp.text().await.expect("response body")
}

// ===== Single-hash cracking =====

#[tokio::test]
async fn crack_md5_password() {
    let body = crack("5f4dcc3b5aa765d61d8327deb882cf99").await;
    assert_eq!(
        results(&body),
        vec![ResultRow::full(
            "5f4dcc3b5aa765d61d8327deb882cf99",
            "md5",
            "password"
        )]
    );
}

#[tokio::test]
async fn crack_sha1_password() {
    let body = crack("5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8").await;
    assert_eq!(
        results(&body),
        vec![ResultRow::full(
            "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8",
            "sha1",
            "password"
        )]
    );
}

#[tokio::test]
async fn crack_sha256_password() {
    let hash = "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8";
    let body = crack(hash).await;
    assert_eq!(
        results(&body),
        vec![ResultRow::full(hash, "sha256", "password")]
    );
}

#[tokio::test]
async fn unknown_hash_not_found() {
    let hash = "0000000000000000000000000000000000000000";
    let body = crack(hash).await;
    assert_eq!(results(&body), vec![ResultRow::not_found(hash)]);
}

#[tokio::test]
async fn multiple_hashes_mixed() {
    let body = crack(
        "5f4dcc3b5aa765d61d8327deb882cf99\n0000000000000000000000000000000000000000",
    )
    .await;
    assert_eq!(
        results(&body),
        vec![
            ResultRow::full("5f4dcc3b5aa765d61d8327deb882cf99", "md5", "password"),
            ResultRow::not_found("0000000000000000000000000000000000000000"),
        ]
    );
}

// ===== Input rejection =====

#[tokio::test]
async fn too_many_hashes_error() {
    let hashes = (0..21)
        .map(|i| format!("{:032x}", i))
        .collect::<Vec<_>>()
        .join("\n");
    let body = crack(&hashes).await;

    assert_eq!(
        extract_error(&body).as_deref(),
        Some("Please enter 20 or less hashes.")
    );
    assert_eq!(
        parse_results(&body),
        None,
        "a rejected submission must not render a results table"
    );
}

#[tokio::test]
async fn empty_form_no_crash() {
    let body = crack("").await;

    assert_body_contains(&body, "Free Password Hash Cracker", "should still show form");
    assert_eq!(
        parse_results(&body),
        None,
        "empty input must not render a results table"
    );
    assert_eq!(extract_error(&body), None, "empty input is not an error");
}

#[tokio::test]
async fn results_table_structure() {
    let body = crack("5f4dcc3b5aa765d61d8327deb882cf99").await;
    assert_body_contains(
        &body,
        "<tr><th>Hash</th><th>Type</th><th>Result</th></tr>",
        "results table should have the Hash/Type/Result header row",
    );
    assert_eq!(
        results(&body),
        vec![ResultRow::full(
            "5f4dcc3b5aa765d61d8327deb882cf99",
            "md5",
            "password"
        )]
    );
}

// ===== Captcha enforcement =====

/// A POST with no captcha token must be rejected outright: an error, no results,
/// and the submitted hashes preserved so the user does not have to retype them.
#[tokio::test]
async fn no_captcha_fails() {
    let hash = "5f4dcc3b5aa765d61d8327deb882cf99";
    let resp = client()
        .post(url("/"))
        .header(ORIGIN, origin())
        .form(&[("hashes", hash)])
        .send()
        .await
        .unwrap();

    assert_success(&resp, "no captcha");
    let body = resp.text().await.unwrap();

    assert_eq!(
        extract_error(&body).as_deref(),
        Some("Incorrect captcha. Please try again.")
    );
    assert_eq!(
        parse_results(&body),
        None,
        "a captcha failure must not crack anything"
    );
    assert_eq!(
        submitted_hashes_textarea(&body),
        hash,
        "textarea should be repopulated with the submitted hash"
    );
}

/// A wrong bypass secret must not grant bypass — the request falls through to real
/// captcha verification and is rejected.
#[tokio::test]
async fn wrong_bypass_secret_fails() {
    let hash = "5f4dcc3b5aa765d61d8327deb882cf99";
    let resp = client()
        .post(url("/"))
        .header(ORIGIN, origin())
        .header("X-Captcha-Bypass", "wrong-secret-value")
        .form(&[("hashes", hash)])
        .send()
        .await
        .unwrap();

    assert_success(&resp, "wrong bypass secret");
    let body = resp.text().await.unwrap();

    assert_eq!(
        extract_error(&body).as_deref(),
        Some("Incorrect captcha. Please try again.")
    );
    assert_eq!(
        parse_results(&body),
        None,
        "a wrong bypass secret must not crack anything"
    );
    assert_eq!(
        submitted_hashes_textarea(&body),
        hash,
        "textarea should be repopulated with the submitted hash"
    );
}

#[tokio::test]
async fn submitted_hashes_echoed_back() {
    let hash = "5f4dcc3b5aa765d61d8327deb882cf99";
    let body = crack(hash).await;
    assert_eq!(submitted_hashes_textarea(&body), hash);
}

/// The one captcha test whose verdict comes from Google.
///
/// A token that is present and plausibly sized passes the server's local checks and is
/// relayed to `siteverify`, which rejects it because Google never issued it. That path
/// -- outbound request, real secret, real answer -- is exercised by nothing else:
/// `no_captcha_fails` and `wrong_bypass_secret_fails` are both refused locally.
///
/// Asserting the exact message matters. "Could not verify captcha (server error)" is
/// the *other* rejection the page can show, and it means the request never completed;
/// accepting it here would let a network failure masquerade as a passing test.
#[tokio::test]
#[ignore = "needs a server with a real reCAPTCHA secret; see require_captcha_enforcement"]
async fn invalid_token_rejected_by_google() {
    require_captcha_enforcement("invalid_token_rejected_by_google");

    let token = plausible_but_invalid_token();
    assert!(
        (500..=2000).contains(&token.len()),
        "token must sit inside the range the server relays ({} bytes), or it is refused \
         locally and Google is never asked",
        token.len()
    );

    let hash = "5f4dcc3b5aa765d61d8327deb882cf99";
    let resp = client()
        .post(url("/"))
        .header(ORIGIN, origin())
        .form(&[("hashes", hash), ("g-recaptcha-response", token.as_str())])
        .send()
        .await
        .expect("request failed");

    assert_success(&resp, "invalid captcha token");
    let body = resp.text().await.expect("response body");

    assert_eq!(
        extract_error(&body).as_deref(),
        Some("Incorrect captcha. Please try again."),
        "expected Google's verdict; a server-error message would mean the round trip failed"
    );
    assert_eq!(
        parse_results(&body),
        None,
        "a captcha failure must not crack anything"
    );
    assert_eq!(
        submitted_hashes_textarea(&body),
        hash,
        "textarea should be repopulated with the submitted hash"
    );
}

/// Production's wordlist is assembled from breach dumps, so some words are not valid
/// UTF-8. The dev list carries `inv\xff\xfeword` for exactly this path.
///
/// Rendering those with `from_utf8_lossy` alone put a string that does *not* hash to the
/// query on a green "exact match" row, with nothing to say a substitution had happened.
/// The row now shows the exact bytes, which are the real answer and can be copied, with
/// the lossy form after them.
#[tokio::test]
async fn a_plaintext_that_is_not_utf8_is_shown_as_bytes() {
    if !dev_fixture_only("a_plaintext_that_is_not_utf8_is_shown_as_bytes") {
        return;
    }
    let md5 = "3e2a8a4ded081ff3ce11a235d3e22150";
    let sha1 = "92874f693e663118f8d3c4d6c6b33562fcaf1caa";
    let shown = "Binary data: 696e76fffe776f7264 (inv\u{fffd}\u{fffd}word)";

    let body = crack(&[md5, sha1].join("\n")).await;

    assert_eq!(
        results(&body),
        vec![
            ResultRow::full(md5, "md5", shown),
            ResultRow::full(sha1, "sha1", shown),
        ]
    );

    // The bytes must reach the page literally; a rendering that only showed the lossy
    // form would still contain the parenthesised half and pass a weaker assertion.
    assert_body_contains(&body, "696e76fffe776f7264", "the exact plaintext bytes");
}

// ===== Request body limit =====

/// Send a form-encoded body of exactly `len` bytes and return the status.
async fn post_body_of(len: usize) -> u16 {
    let mut body = String::from("hashes=");
    while body.len() < len {
        body.push_str("a&");
    }
    body.truncate(len);

    client()
        .post(url("/"))
        .header(ORIGIN, origin())
        .header("X-Captcha-Bypass", captcha_bypass_secret())
        .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(body)
        .send()
        .await
        .expect("request failed")
        .status()
        .as_u16()
}

/// The body cap exists because of what the handler builds from a body, not the body
/// itself: `form_urlencoded::parse(..).collect()` produces 64 bytes of `Vec` per pair,
/// and the densest input expressible is the two-byte `a&`. Measured against the old
/// 100 MB cap, a 10 MB body of exactly this shape drove the server's peak RSS from
/// 17 MB to 267 MB; under the current cap the same body is refused unread.
#[tokio::test]
async fn an_oversized_body_is_refused() {
    assert_eq!(
        post_body_of(400 * 1024).await,
        413,
        "a body over the cap must be refused, and with the status that says why"
    );
}

/// The cap must stay clear of anything the form can legitimately send, or the fix
/// would break real submissions rather than the attack.
#[tokio::test]
async fn a_body_within_the_cap_is_accepted() {
    assert_eq!(post_body_of(120 * 1024).await, 200);
}

// ===== Algorithm coverage =====

/// Submit hash("hello") for all 15 algorithms in one request.
/// LM produces 3 rows because hello/Hello/HELLO share an LM hash.
#[tokio::test]
async fn crack_all_hash_types() {
    let lm = "fda95fbeca288d44aad3b435b51404ee";
    let ntlm = "066ddfd4ef0e9cd7c256fe77191ef43c";
    let mysql = "6b4f89a54e2d27ecd7e8da05b4ab8fd9d1d8b119";
    let md5md5 = "69a329523ce1ec88bf63061863d9cb14";
    let md5 = "5d41402abc4b2a76b9719d911017c592";
    let sha1 = "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d";
    let md2 = "a9046c73e00331af68917d3804f70655";
    let md4 = "866437cb7a794bce2b727acc0362ee27";
    let sha256 = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
    let sha224 = "ea09ae9cc6768c50fcee903ed054556e5bfc8347907f12598aa24193";
    let sha384 = "59e1748777448c69de6b800d7a33bbfb9ff1b463e44354c3553bcdb9c666fa90125a3c79f90397bdf5f6a13de828684f";
    let sha512 = "9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca72323c3d99ba5c11d7c7acc6e14b8c5da0c4663475c2e5c3adef46f73bcdec043";
    let whirlpool = "0a25f55d7308eca6b9567a7ed3bd1b46327f0f1ffdc804dd8bb5af40e88d78b88df0d002a89e2fdbd5876c523f1b67bc44e9f87047598e7548298ea1c81cfd73";
    let ripemd160 = "108f07b8382412612c048d07d13f814118445acd";
    let qubes = "0244dd76e6c94cf2965081473c254eaa3ae0178c206fb7e5f059093faf873e6e7e4f82be6d694708180349a60253b155fdeb7fce9e72523ba450a430f5bcbf77";

    let hashes = [
        lm, ntlm, mysql, md5md5, md5, sha1, md2, md4, sha256, sha224, sha384, sha512, whirlpool,
        ripemd160, qubes,
    ]
    .join("\n");
    let body = crack(&hashes).await;

    let rows = results(&body);

    // LM is case-insensitive, so how many rows it produces is a property of the
    // wordlist: three in dev, thirty-two in production. Split them off and check the
    // property; the other fourteen algorithms each owe exactly one row.
    let (lm_rows, others): (Vec<_>, Vec<_>) = rows.into_iter().partition(|row| row.hash == lm);
    assert_lm_rows_are_case_variants_of(&lm_rows, "HELLO");

    assert_eq!(
        others,
        vec![
            ResultRow::full(ntlm, "NTLM", "hello"),
            ResultRow::full(mysql, "MySQL4.1+", "hello"),
            ResultRow::full(md5md5, "md5(md5)", "hello"),
            ResultRow::full(md5, "md5", "hello"),
            ResultRow::full(sha1, "sha1", "hello"),
            ResultRow::full(md2, "md2", "hello"),
            ResultRow::full(md4, "md4", "hello"),
            ResultRow::full(sha256, "sha256", "hello"),
            ResultRow::full(sha224, "sha224", "hello"),
            ResultRow::full(sha384, "sha384", "hello"),
            ResultRow::full(sha512, "sha512", "hello"),
            ResultRow::full(whirlpool, "whirlpool", "hello"),
            ResultRow::full(ripemd160, "ripemd160", "hello"),
            ResultRow::full(qubes, "QubesV3.1BackupDefaults", "hello"),
        ],
        "every algorithm but LM owes exactly one row -- one per algorithm also proves \
         the full-match short circuit, since md5 and sha1 would otherwise be found a \
         second time in their huge tables"
    );
}

/// Assert a set of LM rows is exactly the case spellings of one word.
///
/// How many spellings the dictionary holds is not the server's business; that they all
/// uppercase to the same string, all count as full matches, and number more than one is.
fn assert_lm_rows_are_case_variants_of(rows: &[ResultRow], upper: &str) {
    let (shown, truncation): (Vec<_>, Vec<_>) = rows.iter().partition(|row| row.class != "more");

    assert!(
        shown.len() >= 2,
        "LM is case-insensitive, so at least two spellings must be found, got {:?}",
        shown
    );
    for row in &shown {
        assert_eq!(
            row.class, "suc",
            "an LM case variant is a full match: {:?}",
            row
        );
        assert_eq!(row.hash_type, "LM", "wrong algorithm: {:?}", row);
        assert_eq!(
            row.result.to_uppercase(),
            upper,
            "every LM match must uppercase to the queried word: {:?}",
            row
        );
    }

    let distinct: std::collections::BTreeSet<_> = shown.iter().map(|r| &r.result).collect();
    assert_eq!(
        distinct.len(),
        shown.len(),
        "the same spelling must not be listed twice: {:?}",
        shown
    );

    if let Some(more) = truncation.first() {
        let (hidden, total) = truncation_counts(more);
        assert_eq!(
            shown.len(),
            RESULT_LIMIT,
            "a capped hash shows exactly the limit"
        );
        assert_eq!(
            hidden,
            total - RESULT_LIMIT,
            "hidden must be total minus shown"
        );
    }
}

/// LM uppercases before hashing, so every case spelling of a word shares one hash and
/// all of them come back. Which spellings exist is the dictionary's business -- three in
/// dev, thirty-two in production -- so this asserts the relationship between them.
#[tokio::test]
async fn lm_case_insensitive_matches() {
    let lm = "fda95fbeca288d44aad3b435b51404ee";
    let rows = results(&crack(lm).await);

    assert!(!rows.is_empty(), "LM(hello) must crack");
    for row in &rows {
        assert_eq!(
            row.hash, lm,
            "every row answers the submitted hash: {:?}",
            row
        );
    }
    assert_lm_rows_are_case_variants_of(&rows, "HELLO");
}

// ===== Prefix and mixed results =====

/// Hashes sharing the first 8 bytes with hash("monkey") but with zeroed suffixes
/// must come back as partial (yellow) matches, never full ones.
#[tokio::test]
async fn prefix_match_partial_results() {
    let md5_prefix = "d0763edaa9d9bd2a0000000000000000";
    let sha1_prefix = "ab87d24bdc7452e5000000000000000000000000";
    let sha256_prefix = "000c285457fc971f000000000000000000000000000000000000000000000000";

    // What the rows show is monkey's real digests, not the zero-padded queries.
    let md5_monkey = "d0763edaa9d9bd2a9516280e9044d885";
    let sha1_monkey = "ab87d24bdc7452e55738deb5f868e1f16dea5ace";
    let sha256_monkey = "000c285457fc971f862a79b786476c78812c8897063c6fa9c045f579a3b2d63f";

    let body = crack(&[md5_prefix, sha1_prefix, sha256_prefix].join("\n")).await;

    let rows = results(&body);

    // A prefix query may never be reported as a full match, whatever the wordlist holds.
    for row in &rows {
        assert_eq!(
            row.class, "part",
            "a query matching only a prefix must be yellow, never green: {:?}",
            row
        );
    }

    // Repeats appear when a word is in both an algorithm's small and huge table.
    assert_eq!(
        collapse_repeats(rows),
        vec![
            ResultRow::partial(md5_monkey, "md5", "monkey"),
            ResultRow::partial(sha1_monkey, "sha1", "monkey"),
            ResultRow::partial(sha256_monkey, "sha256", "monkey"),
        ]
    );

    // The zero tails were never part of any digest, so nothing may present them as one.
    for query in [md5_prefix, sha1_prefix, sha256_prefix] {
        assert_body_does_not_contain(&body, &format!("<td>{}</td>", query), "near-miss row");
    }

    // The agreeing head is marked up, and stops exactly where agreement stops.
    assert_body_contains(
        &body,
        "<span class=\"matched\">d0763edaa9d9bd2a</span>9516280e9044d885",
        "md5 near-miss hash cell",
    );
}

/// One request mixing every result type, verifying all four row kinds coexist.
#[tokio::test]
async fn mixed_full_prefix_not_found_format_error() {
    let md5_hello = "5d41402abc4b2a76b9719d911017c592";
    let sha1_hello = "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d";
    let md5_prefix = "d0763edaa9d9bd2a0000000000000000";
    let missing = "0000000000000000000000000000000000000000";
    let invalid = "not-a-hex-hash";

    let body = crack(&[md5_hello, sha1_hello, md5_prefix, missing, invalid].join("\n")).await;

    assert_eq!(
        collapse_repeats(results(&body)),
        vec![
            ResultRow::full(md5_hello, "md5", "hello"),
            ResultRow::full(sha1_hello, "sha1", "hello"),
            ResultRow::partial(MD5_MONKEY, "md5", "monkey"),
            ResultRow::not_found(missing),
            ResultRow::bad_format(invalid),
        ]
    );
}

// ===== Result count limit =====

/// LM's index prefix is DES of the uppercased first seven characters, so every
/// "password*" word in the dictionary shares one: a query against that block finds one
/// exact match and 29 near misses, and the table shows 20 with a row for the rest.
///
/// The hash queried is LM("password123") for a reason. Entries in a block are visited
/// in index order, and "password123" sits 26th of the 30 — past the cap — so an
/// implementation that simply stopped after 20 entries would drop the one row that
/// answers the question and report the hash as uncracked. Re-derive the order with:
///
/// ```text
/// preimage lookup -a LM -i dev/cracking/lm.idx -d dev/cracking/REALUNIQ.lst \
///     e52cac67419a9a220000000000000000
/// ```
///
/// The near misses below are therefore the block's first 19 in that order, and pinning
/// them exactly is what keeps this test honest: if the ordering ever changes so that
/// "password123" lands inside the cap, this fails rather than quietly passing while
/// testing nothing.
#[tokio::test]
async fn oversized_collision_block_is_capped_and_reports_the_remainder() {
    let lm = "e52cac67419a9a22664345140a852f61";
    // Each near miss shows its own digest, which is why they are listed with one. They
    // all open with the 8-byte index prefix the query matched -- that is what put them
    // in this block -- and diverge immediately after it.
    let rows = results(&crack(lm).await);
    assert_capped_block(&rows, "e52cac67419a9a22", "PASSWORD123");
}

/// Assert a capped result set for one hash: the limit of rows, then a `more` row whose
/// counts add up, with the exact match present among the rows shown.
///
/// The last part is the point. Entries in a collision block are visited in index order
/// and the exact match need not be near the front -- it is 26th of 30 in dev and further
/// back in production -- so an implementation that simply stopped after the first
/// `RESULT_LIMIT` entries would drop the one row that answers the question and report
/// the hash as uncracked. What is asserted is that it survives the cap, not where the
/// dictionary happens to put it.
fn assert_capped_block(rows: &[ResultRow], index_prefix: &str, upper: &str) {
    let (more, shown) = rows.split_last().expect("a capped hash must produce rows");

    let (hidden, total) = truncation_counts(more);
    assert_eq!(
        shown.len(),
        RESULT_LIMIT,
        "a capped hash shows exactly the limit"
    );
    assert_eq!(
        hidden,
        total - RESULT_LIMIT,
        "hidden must be total minus shown"
    );
    assert!(
        total > RESULT_LIMIT,
        "nothing was truncated, so this tests nothing"
    );

    // Full matches are hoisted above the near misses, so the shown rows split cleanly.
    let boundary = shown.partition_point(|row| row.class == "suc");
    let (exact, near_misses) = shown.split_at(boundary);

    // At least one, not exactly one: LM is case-insensitive, so every case spelling of
    // the word that is in the dictionary is a full match -- one in dev, five in
    // production. What must hold on any wordlist is that the cap did not swallow them.
    assert!(
        !exact.is_empty(),
        "an exact match must survive the cap, wherever index order puts it: {:?}",
        shown
    );
    for row in exact {
        assert_eq!(
            row.result.to_uppercase(),
            upper,
            "a full match must be the queried word: {:?}",
            row
        );
    }

    for row in near_misses {
        assert_eq!(
            row.class, "part",
            "every full match must precede every near miss: {:?}",
            shown
        );
        assert!(
            row.hash.starts_with(index_prefix),
            "a near miss shares the index prefix {} that put it in this block: {:?}",
            index_prefix,
            row
        );
    }
}

/// The limit is spent per submitted hash. A hash that hits the cap must not consume
/// another hash's rows, and must not put a truncation row on a result set that is
/// hiding nothing.
#[tokio::test]
async fn the_limit_is_spent_per_hash_not_per_request() {
    let lm = "e52cac67419a9a22664345140a852f61";
    let md5_hello = "5d41402abc4b2a76b9719d911017c592";
    let rows = results(&crack(&[lm, md5_hello].join("\n")).await);

    assert_eq!(
        rows.len(),
        RESULT_LIMIT + 2,
        "the limit plus a truncation row for the capped hash, then one for the other"
    );
    assert_capped_block(&rows[..=RESULT_LIMIT], "e52cac67419a9a22", "PASSWORD123");
    assert_eq!(
        rows[RESULT_LIMIT + 1],
        ResultRow::full(md5_hello, "md5", "hello"),
        "the second hash gets its own budget and no truncation row"
    );
}

#[tokio::test]
async fn unrecognized_hash_format() {
    let too_short = "abcdef0123456";
    let non_hex = "xyz0000000000000000";
    let odd_length = "abcdef01234567890";

    let body = crack(&[too_short, non_hex, odd_length].join("\n")).await;

    assert_eq!(
        results(&body),
        vec![
            ResultRow::bad_format(too_short),
            ResultRow::bad_format(non_hex),
            ResultRow::bad_format(odd_length),
        ]
    );
}

// ===== Dictionary separation =====

/// "elephant" is only in HUGELIST.lst, so the huge fallback tables must find it.
#[tokio::test]
async fn word_only_in_huge_dictionary() {
    let md5_elephant = "e4b48fd541b3dcb99cababc87c2ee88f";
    let sha1_elephant = "0ae9e4deba26021986ffd99636da6601f6393631";

    let body = crack(&[md5_elephant, sha1_elephant].join("\n")).await;

    assert_eq!(
        results(&body),
        vec![
            ResultRow::full(md5_elephant, "md5", "elephant"),
            ResultRow::full(sha1_elephant, "sha1", "elephant"),
        ]
    );
}

/// "monkey" is only in REALUNIQ.lst, so the regular tables must find it.
#[tokio::test]
async fn word_only_in_small_dictionary() {
    let md5_monkey = "d0763edaa9d9bd2a9516280e9044d885";
    let sha1_monkey = "ab87d24bdc7452e55738deb5f868e1f16dea5ace";

    let body = crack(&[md5_monkey, sha1_monkey].join("\n")).await;

    assert_eq!(
        results(&body),
        vec![
            ResultRow::full(md5_monkey, "md5", "monkey"),
            ResultRow::full(sha1_monkey, "sha1", "monkey"),
        ]
    );
}

/// "hello" is in both dictionaries. Exact whole-table equality is what proves the
/// early-exit dedup works: a duplicate row from the huge table would be an extra
/// element and fail the comparison.
///
/// This holds on any wordlist, because the early exit is unconditional once a *full*
/// match is found -- the port reproduces PHP's `break 2` in CrackHashes.php, whose own
/// comment gives avoiding md5/md5-huge duplication as the reason.
///
/// A *prefix* match is the opposite case and deliberately so: no full match means no
/// early exit, so every table is searched and a word in two of them is listed twice.
/// PHP does the same. That is why the row-sequence tests above call `collapse_repeats`
/// -- whether the two dictionaries overlap on a given word is a property of the
/// wordlist, and they do not overlap on `monkey` in dev but do in production.
#[tokio::test]
async fn word_in_both_dictionaries_no_duplicate() {
    let md5_hello = "5d41402abc4b2a76b9719d911017c592";
    let sha1_hello = "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d";

    let body = crack(&[md5_hello, sha1_hello].join("\n")).await;

    assert_eq!(
        results(&body),
        vec![
            ResultRow::full(md5_hello, "md5", "hello"),
            ResultRow::full(sha1_hello, "sha1", "hello"),
        ]
    );
}

// ===== XSS regression tests =====

/// Askama auto-escaping must neutralize a script tag in both the echoed textarea
/// and the result row. The raw-payload check stays a whole-body search on purpose:
/// the security property is that the raw tag appears *nowhere* on the page.
#[tokio::test]
async fn xss_script_tag_escaped_in_textarea_and_results() {
    let payload = "<script>alert('xss')</script>";

    let body = crack(payload).await;

    assert_body_does_not_contain(&body, "<script>alert(", "raw <script> tag must be escaped");
    // The cell's text is the payload verbatim only because it was escaped into a
    // text node. Had it been emitted raw, it would have parsed as a <script>
    // element and the text would be just "alert('xss')".
    assert_eq!(results(&body), vec![ResultRow::bad_format(payload)]);
    assert_eq!(submitted_hashes_textarea(&body), payload);
}

#[tokio::test]
async fn xss_quotes_and_attributes_escaped() {
    let payload = "\" onmouseover=\"alert(1)\" x=\"";

    let body = crack(payload).await;

    assert_body_does_not_contain(
        &body,
        "onmouseover=\"alert(1)\"",
        "attribute injection must be escaped",
    );
    assert_eq!(results(&body), vec![ResultRow::bad_format(payload)]);
    assert_eq!(submitted_hashes_textarea(&body), payload);
}

#[tokio::test]
async fn xss_html_in_hash_column_escaped() {
    let payload = "<img src=x onerror=alert(1)>";

    let body = crack(payload).await;

    assert_body_does_not_contain(&body, "<img src=x", "raw <img> tag must be escaped");
    // <img> is a void element: emitted raw it would contribute no text at all,
    // so recovering the payload verbatim proves it was escaped.
    assert_eq!(results(&body), vec![ResultRow::bad_format(payload)]);
}

// ===== Input normalization tests =====

#[tokio::test]
async fn input_normalization_windows_line_endings() {
    let md5_password = "5f4dcc3b5aa765d61d8327deb882cf99";
    let md5_hello = "5d41402abc4b2a76b9719d911017c592";

    let body = crack(&format!("{}\r\n{}", md5_password, md5_hello)).await;

    assert_eq!(
        results(&body),
        vec![
            ResultRow::full(md5_password, "md5", "password"),
            ResultRow::full(md5_hello, "md5", "hello"),
        ]
    );
}

#[tokio::test]
async fn input_normalization_bare_cr() {
    let md5_password = "5f4dcc3b5aa765d61d8327deb882cf99";
    let md5_hello = "5d41402abc4b2a76b9719d911017c592";

    let body = crack(&format!("{}\r{}", md5_password, md5_hello)).await;

    assert_eq!(
        results(&body),
        vec![
            ResultRow::full(md5_password, "md5", "password"),
            ResultRow::full(md5_hello, "md5", "hello"),
        ]
    );
}

/// MySQL's PASSWORD() prints hashes wrapped in asterisks; those get stripped.
#[tokio::test]
async fn input_normalization_mysql_asterisks() {
    let sha1_password = "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8";
    let body = crack(&format!("*{}*", sha1_password)).await;

    assert_eq!(
        results(&body),
        vec![ResultRow::full(sha1_password, "sha1", "password")]
    );
}

#[tokio::test]
async fn input_normalization_whitespace_trimming() {
    let md5_password = "5f4dcc3b5aa765d61d8327deb882cf99";
    let md5_hello = "5d41402abc4b2a76b9719d911017c592";

    let body = crack(&format!("  {}  \n\t{}\t", md5_password, md5_hello)).await;

    assert_eq!(
        results(&body),
        vec![
            ResultRow::full(md5_password, "md5", "password"),
            ResultRow::full(md5_hello, "md5", "hello"),
        ]
    );
}

// ===== Result ordering =====

/// The cracking core separates valid from invalid hashes, batches the valid ones to
/// the oracle, then reassembles. Comparing the whole table in order is what catches
/// a reassembly bug.
#[tokio::test]
async fn results_preserve_submission_order() {
    let md5_hello = "5d41402abc4b2a76b9719d911017c592";
    let invalid = "not-a-hex-hash";
    let missing = "0000000000000000000000000000000000000000";
    let sha1_password = "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8";
    let md5_prefix = "d0763edaa9d9bd2a0000000000000000";

    let body = crack(&[md5_hello, invalid, missing, sha1_password, md5_prefix].join("\n")).await;

    assert_eq!(
        collapse_repeats(results(&body)),
        vec![
            ResultRow::full(md5_hello, "md5", "hello"),
            ResultRow::bad_format(invalid),
            ResultRow::not_found(missing),
            ResultRow::full(sha1_password, "sha1", "password"),
            ResultRow::partial(MD5_MONKEY, "md5", "monkey"),
        ]
    );
}

// ===== Empty-word regression test =====

/// Production's REALUNIQ.lst contains an empty line — confirmed on the live PHP
/// server, where sha256("") cracks and returns the empty string. SHA-256 accepts any
/// byte string, so only the empty word itself can verify against that hash. The dev
/// wordlist carries a matching empty line.
///
/// This is the case where substring assertions are worthless: `contains("")` is
/// vacuously true, so only exact row comparison can tell success from failure.
#[tokio::test]
async fn crack_empty_string_returns_empty_plaintext() {
    let sha256_empty = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    let ntlm_empty = "31d6cfe0d16ae931b73c59d7e0c089c0";

    let body = crack(&[sha256_empty, ntlm_empty].join("\n")).await;

    assert_eq!(
        results(&body),
        vec![
            ResultRow::full(sha256_empty, "sha256", ""),
            ResultRow::full(ntlm_empty, "NTLM", ""),
        ]
    );
}

/// A third-party page can make a visitor's browser POST here. If the server accepted
/// it, it would report that visitor's IP to Google as a CrackStation submission and
/// record a hit under their address -- neither of which they did.
///
/// CORS headers cannot prevent this: a form POST of application/x-www-form-urlencoded
/// is a CORS "simple request", so it is delivered and executed regardless of any
/// Access-Control-Allow-Origin. The refusal has to happen server-side, on Origin.
#[tokio::test]
async fn cross_origin_post_is_refused() {
    for bad_origin in ["https://evil.com", "https://crackstation.net.evil.com"] {
        let resp = client()
            .post(url("/"))
            .header(ORIGIN, bad_origin)
            .header("X-Captcha-Bypass", captcha_bypass_secret())
            .form(&[("hashes", "25d55ad283aa400af464c76d713c07ad")])
            .send()
            .await
            .expect("request failed");

        assert_eq!(
            resp.status().as_u16(),
            403,
            "POST from {bad_origin} must be refused"
        );
        let body = resp.text().await.expect("body");
        assert!(
            !body.contains("12345678"),
            "a refused cross-origin POST must not return a cracked plaintext"
        );
    }
}

/// A POST carrying no Origin and no Referer is refused too -- there is nothing to
/// distinguish it from a forged one.
#[tokio::test]
async fn post_without_origin_or_referer_is_refused() {
    let resp = client()
        .post(url("/"))
        .header("X-Captcha-Bypass", captcha_bypass_secret())
        .form(&[("hashes", "25d55ad283aa400af464c76d713c07ad")])
        .send()
        .await
        .expect("request failed");

    assert_eq!(resp.status().as_u16(), 403);
}
