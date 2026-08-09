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

use common::{
    assert_body_contains, assert_body_does_not_contain, assert_success, captcha_bypass_secret,
    client, is_production_url, parse_results, results, submitted_hashes_textarea, url,
    ResultRow,
};

/// Captcha *rejection* is unreachable in dev: `dev/dotenv-example` sets
/// `RECAPTCHA_SECRET_KEY` to Google's test secret, which validates any token —
/// including an absent one — so a captcha-less POST still cracks successfully.
///
/// Tests needing a real rejection are therefore marked `#[ignore]`, so a default run
/// reports them under "ignored" rather than counting them as passes. Run them with:
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
        "{} requires a server that actually rejects captchas, but CRACKSTATION_URL points at \
         a dev server using Google's always-pass test secret — captcha rejection cannot occur \
         there, so this test would verify nothing. Point CRACKSTATION_URL at production.",
        test_name
    );
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
#[ignore = "needs a server that enforces captcha; see require_captcha_enforcement"]
async fn no_captcha_fails() {
    require_captcha_enforcement("no_captcha_fails");
    let hash = "5f4dcc3b5aa765d61d8327deb882cf99";
    let resp = client()
        .post(url("/"))
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
#[ignore = "needs a server that enforces captcha; see require_captcha_enforcement"]
async fn wrong_bypass_secret_fails() {
    require_captcha_enforcement("wrong_bypass_secret_fails");
    let hash = "5f4dcc3b5aa765d61d8327deb882cf99";
    let resp = client()
        .post(url("/"))
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

    assert_eq!(
        results(&body),
        vec![
            ResultRow::full(lm, "LM", "hello"),
            ResultRow::full(lm, "LM", "Hello"),
            ResultRow::full(lm, "LM", "HELLO"),
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
        ]
    );
}

/// LM uppercases before hashing, so all three case variants share one hash.
#[tokio::test]
async fn lm_case_insensitive_matches() {
    let lm = "fda95fbeca288d44aad3b435b51404ee";
    let body = crack(lm).await;
    assert_eq!(
        results(&body),
        vec![
            ResultRow::full(lm, "LM", "hello"),
            ResultRow::full(lm, "LM", "Hello"),
            ResultRow::full(lm, "LM", "HELLO"),
        ]
    );
}

// ===== Prefix and mixed results =====

/// Hashes sharing the first 8 bytes with hash("monkey") but with zeroed suffixes
/// must come back as partial (yellow) matches, never full ones.
#[tokio::test]
async fn prefix_match_partial_results() {
    let md5_prefix = "d0763edaa9d9bd2a0000000000000000";
    let sha1_prefix = "ab87d24bdc7452e5000000000000000000000000";
    let sha256_prefix = "000c285457fc971f000000000000000000000000000000000000000000000000";

    let body = crack(&[md5_prefix, sha1_prefix, sha256_prefix].join("\n")).await;

    assert_eq!(
        results(&body),
        vec![
            ResultRow::partial(md5_prefix, "md5", "monkey"),
            ResultRow::partial(sha1_prefix, "sha1", "monkey"),
            ResultRow::partial(sha256_prefix, "sha256", "monkey"),
        ]
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
        results(&body),
        vec![
            ResultRow::full(md5_hello, "md5", "hello"),
            ResultRow::full(sha1_hello, "sha1", "hello"),
            ResultRow::partial(md5_prefix, "md5", "monkey"),
            ResultRow::not_found(missing),
            ResultRow::bad_format(invalid),
        ]
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
        results(&body),
        vec![
            ResultRow::full(md5_hello, "md5", "hello"),
            ResultRow::bad_format(invalid),
            ResultRow::not_found(missing),
            ResultRow::full(sha1_password, "sha1", "password"),
            ResultRow::partial(md5_prefix, "md5", "monkey"),
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
