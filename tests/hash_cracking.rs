//! Hash cracking tests
//!
//! Tests for the hash cracking form and results.
//! All POST tests use the X-Captcha-Bypass header to skip reCAPTCHA.

mod common;

use common::{
    assert_body_contains, assert_body_does_not_contain, assert_success, client,
    captcha_bypass_secret, url,
};

/// Extract the content of the `<textarea name="hashes" ...>...</textarea>` element.
fn extract_textarea(body: &str) -> &str {
    let name_attr = "name=\"hashes\"";
    let name_pos = body.find(name_attr)
        .unwrap_or_else(|| panic!("no textarea with {} found in body", name_attr));
    let after_name = &body[name_pos..];
    let content_start = after_name.find('>')
        .expect("no '>' after textarea name attribute") + 1;
    let content_region = &after_name[content_start..];
    let content_end = content_region.find("</textarea>")
        .expect("no closing </textarea> tag found");
    &content_region[..content_end]
}

/// Submit the MD5 of "password" and verify it's cracked.
#[tokio::test]
async fn crack_md5_password() {
    let resp = client()
        .post(url("/"))
        .header("X-Captcha-Bypass", captcha_bypass_secret())
        .form(&[("hashes", "5f4dcc3b5aa765d61d8327deb882cf99")])
        .send()
        .await
        .unwrap();

    assert_success(&resp, "crack md5(password)");
    let body = resp.text().await.unwrap();
    assert_body_contains(&body, "password", "should find plaintext 'password'");
    assert_body_contains(&body, "class=\"suc\"", "should have green success row");
}

/// Submit the SHA1 of "password" and verify it's cracked.
#[tokio::test]
async fn crack_sha1_password() {
    let resp = client()
        .post(url("/"))
        .header("X-Captcha-Bypass", captcha_bypass_secret())
        .form(&[("hashes", "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8")])
        .send()
        .await
        .unwrap();

    assert_success(&resp, "crack sha1(password)");
    let body = resp.text().await.unwrap();
    assert_body_contains(&body, "password", "should find plaintext 'password'");
    assert_body_contains(&body, "class=\"suc\"", "should have green success row");
}

/// Submit the SHA256 of "password" and verify it's cracked.
#[tokio::test]
async fn crack_sha256_password() {
    let resp = client()
        .post(url("/"))
        .header("X-Captcha-Bypass", captcha_bypass_secret())
        .form(&[(
            "hashes",
            "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",
        )])
        .send()
        .await
        .unwrap();

    assert_success(&resp, "crack sha256(password)");
    let body = resp.text().await.unwrap();
    assert_body_contains(&body, "password", "should find plaintext 'password'");
    assert_body_contains(&body, "class=\"suc\"", "should have green success row");
}

/// Submit an unknown hash and verify it shows "Not found."
#[tokio::test]
async fn unknown_hash_not_found() {
    let resp = client()
        .post(url("/"))
        .header("X-Captcha-Bypass", captcha_bypass_secret())
        .form(&[("hashes", "0000000000000000000000000000000000000000")])
        .send()
        .await
        .unwrap();

    assert_success(&resp, "unknown hash");
    let body = resp.text().await.unwrap();
    assert_body_contains(&body, "Not found.", "should show 'Not found.'");
    assert_body_contains(&body, "class=\"fail\"", "should have red failure row");
}

/// Submit multiple hashes (mix of found and not found).
#[tokio::test]
async fn multiple_hashes_mixed() {
    let hashes = "5f4dcc3b5aa765d61d8327deb882cf99\n0000000000000000000000000000000000000000";
    let resp = client()
        .post(url("/"))
        .header("X-Captcha-Bypass", captcha_bypass_secret())
        .form(&[("hashes", hashes)])
        .send()
        .await
        .unwrap();

    assert_success(&resp, "multiple hashes");
    let body = resp.text().await.unwrap();
    assert_body_contains(&body, "password", "should find 'password' for known hash");
    assert_body_contains(&body, "Not found.", "should show 'Not found.' for unknown hash");
    assert_body_contains(&body, "class=\"suc\"", "should have success row");
    assert_body_contains(&body, "class=\"fail\"", "should have failure row");
}

/// Submit more than 20 hashes and verify error message.
#[tokio::test]
async fn too_many_hashes_error() {
    let hashes = (0..21)
        .map(|i| format!("{:032x}", i))
        .collect::<Vec<_>>()
        .join("\n");

    let resp = client()
        .post(url("/"))
        .header("X-Captcha-Bypass", captcha_bypass_secret())
        .form(&[("hashes", hashes.as_str())])
        .send()
        .await
        .unwrap();

    assert_success(&resp, ">20 hashes");
    let body = resp.text().await.unwrap();
    assert_body_contains(&body, "20 or less", "should show hash limit error");
}

/// Submit empty form and verify no crash.
#[tokio::test]
async fn empty_form_no_crash() {
    let resp = client()
        .post(url("/"))
        .header("X-Captcha-Bypass", captcha_bypass_secret())
        .form(&[("hashes", "")])
        .send()
        .await
        .unwrap();

    assert_success(&resp, "empty form");
    let body = resp.text().await.unwrap();
    // Should render the form without results table
    assert_body_contains(&body, "Free Password Hash Cracker", "should still show form");
    assert_body_does_not_contain(&body, "class=\"results\"", "should not show results table");
}

/// Verify the results table has proper structure.
#[tokio::test]
async fn results_table_structure() {
    let resp = client()
        .post(url("/"))
        .header("X-Captcha-Bypass", captcha_bypass_secret())
        .form(&[("hashes", "5f4dcc3b5aa765d61d8327deb882cf99")])
        .send()
        .await
        .unwrap();

    assert_success(&resp, "results table");
    let body = resp.text().await.unwrap();
    assert_body_contains(&body, "class=\"results\"", "should have results table");
    assert_body_contains(&body, "<th>Hash</th>", "should have Hash column header");
    assert_body_contains(&body, "<th>Type</th>", "should have Type column header");
    assert_body_contains(&body, "<th>Result</th>", "should have Result column header");
}

/// POST without captcha bypass or valid token should fail and repopulate the textarea.
#[tokio::test]
async fn no_captcha_fails() {
    let hash = "5f4dcc3b5aa765d61d8327deb882cf99";
    let resp = client()
        .post(url("/"))
        .form(&[("hashes", hash)])
        .send()
        .await
        .unwrap();

    assert_success(&resp, "no captcha");
    let body = resp.text().await.unwrap();
    assert_body_contains(&body, "captcha", "should show captcha error");
    let textarea_content = extract_textarea(&body);
    assert_eq!(textarea_content, hash, "textarea should be repopulated with submitted hash");
}

/// Wrong captcha bypass secret should fail and repopulate the textarea.
#[tokio::test]
async fn wrong_bypass_secret_fails() {
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
    assert_body_contains(&body, "captcha", "should show captcha error");
    let textarea_content = extract_textarea(&body);
    assert_eq!(textarea_content, hash, "textarea should be repopulated with submitted hash");
}

/// The submitted hashes should be echoed back in the textarea.
#[tokio::test]
async fn submitted_hashes_echoed_back() {
    let hash = "5f4dcc3b5aa765d61d8327deb882cf99";
    let resp = client()
        .post(url("/"))
        .header("X-Captcha-Bypass", captcha_bypass_secret())
        .form(&[("hashes", hash)])
        .send()
        .await
        .unwrap();

    assert_success(&resp, "echo back");
    let body = resp.text().await.unwrap();
    assert_body_contains(&body, hash, "submitted hash should appear in textarea");
}

/// Submit hash("hello") for all 15 algorithms in one request.
/// Each should be cracked with the correct algorithm name and plaintext "hello".
/// LM produces 3 result rows because hello/Hello/HELLO all have the same LM hash.
#[tokio::test]
async fn crack_all_hash_types() {
    let hashes = [
        "fda95fbeca288d44aad3b435b51404ee",                                                                                                     // LM
        "066ddfd4ef0e9cd7c256fe77191ef43c",                                                                                                     // NTLM
        "6b4f89a54e2d27ecd7e8da05b4ab8fd9d1d8b119",                                                                                             // MySQL4.1+
        "69a329523ce1ec88bf63061863d9cb14",                                                                                                     // md5(md5)
        "5d41402abc4b2a76b9719d911017c592",                                                                                                     // md5
        "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d",                                                                                             // sha1
        "a9046c73e00331af68917d3804f70655",                                                                                                     // md2
        "866437cb7a794bce2b727acc0362ee27",                                                                                                     // md4
        "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",                                                                     // sha256
        "ea09ae9cc6768c50fcee903ed054556e5bfc8347907f12598aa24193",                                                                             // sha224
        "59e1748777448c69de6b800d7a33bbfb9ff1b463e44354c3553bcdb9c666fa90125a3c79f90397bdf5f6a13de828684f",                                     // sha384
        "9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca72323c3d99ba5c11d7c7acc6e14b8c5da0c4663475c2e5c3adef46f73bcdec043", // sha512
        "0a25f55d7308eca6b9567a7ed3bd1b46327f0f1ffdc804dd8bb5af40e88d78b88df0d002a89e2fdbd5876c523f1b67bc44e9f87047598e7548298ea1c81cfd73", // whirlpool
        "108f07b8382412612c048d07d13f814118445acd",                                                                                             // ripemd160
        "0244dd76e6c94cf2965081473c254eaa3ae0178c206fb7e5f059093faf873e6e7e4f82be6d694708180349a60253b155fdeb7fce9e72523ba450a430f5bcbf77", // QubesV3.1BackupDefaults
    ]
    .join("\n");

    let resp = client()
        .post(url("/"))
        .header("X-Captcha-Bypass", captcha_bypass_secret())
        .form(&[("hashes", hashes.as_str())])
        .send()
        .await
        .unwrap();

    assert_success(&resp, "crack all hash types");
    let body = resp.text().await.unwrap();

    // Every algorithm should appear in a success row with plaintext "hello"
    for algo in [
        "LM", "NTLM", "MySQL4.1+", "md5(md5)", "md5", "sha1",
        "md2", "md4", "sha256", "sha224", "sha384", "sha512",
        "whirlpool", "ripemd160", "QubesV3.1BackupDefaults",
    ] {
        let needle = format!("<td>{}</td><td>hello</td>", algo);
        assert_body_contains(&body, &needle, &format!("{} should crack 'hello'", algo));
    }

    // LM also returns case variants since it uppercases input before hashing
    assert_body_contains(
        &body,
        "<td>LM</td><td>Hello</td>",
        "LM should return case variant 'Hello'",
    );
    assert_body_contains(
        &body,
        "<td>LM</td><td>HELLO</td>",
        "LM should return case variant 'HELLO'",
    );

    // Exactly 17 success rows: 14 algorithms × 1 match + LM × 3 case variants
    let suc_count = body.matches("class=\"suc\"").count();
    assert_eq!(suc_count, 17, "expected 17 success rows, got {}", suc_count);

    // No failure result rows or format errors (note: "Not found." also appears in the
    // color codes legend, so we match against the result row markup specifically)
    assert_body_does_not_contain(&body, "<td>Not found.</td>", "no hash should be 'Not found.'");
    assert_body_does_not_contain(
        &body,
        "Unrecognized hash format.",
        "no format errors expected",
    );
}

/// Submit hashes that share the first 8 bytes (16 hex chars) with hash("monkey")
/// but have different suffixes. These should produce partial (yellow) matches.
#[tokio::test]
async fn prefix_match_partial_results() {
    // Real hashes: md5("monkey") = d0763edaa9d9bd2a9516280e9044d885
    //              sha1("monkey") = ab87d24bdc7452e55738deb5f868e1f16dea5ace
    //              sha256("monkey") = 000c285457fc971f862a79b786476c78812c8897063c6fa9c045f579a3b2d63f
    // Fake hashes: same first 16 hex chars, zeroed suffix
    let hashes = [
        "d0763edaa9d9bd2a0000000000000000",                                                 // md5 prefix
        "ab87d24bdc7452e5000000000000000000000000",                                         // sha1 prefix
        "000c285457fc971f000000000000000000000000000000000000000000000000",                 // sha256 prefix
    ]
    .join("\n");

    let resp = client()
        .post(url("/"))
        .header("X-Captcha-Bypass", captcha_bypass_secret())
        .form(&[("hashes", hashes.as_str())])
        .send()
        .await
        .unwrap();

    assert_success(&resp, "prefix match");
    let body = resp.text().await.unwrap();

    // Each should produce a partial (yellow) match with plaintext "monkey"
    assert_body_contains(&body, "class=\"part\"", "should have partial match rows");
    assert_body_contains(
        &body,
        "<td>md5</td><td>monkey</td>",
        "md5 prefix should find 'monkey'",
    );
    assert_body_contains(
        &body,
        "<td>sha1</td><td>monkey</td>",
        "sha1 prefix should find 'monkey'",
    );
    assert_body_contains(
        &body,
        "<td>sha256</td><td>monkey</td>",
        "sha256 prefix should find 'monkey'",
    );

    // Exactly 3 partial match rows, one per algorithm
    let part_count = body.matches("class=\"part\"").count();
    assert_eq!(part_count, 3, "expected 3 partial match rows, got {}", part_count);

    // No full matches (the suffixes are wrong) and no failures
    assert_body_does_not_contain(&body, "class=\"suc\"", "should not have full match rows");
    assert_body_does_not_contain(&body, "<td>Not found.</td>", "should not have 'Not found.' rows");
}

/// Submit only the LM hash of "hello" and verify all 3 case variants are returned.
/// LM uppercases input before hashing, so hello/Hello/HELLO all produce the same hash.
#[tokio::test]
async fn lm_case_insensitive_matches() {
    let resp = client()
        .post(url("/"))
        .header("X-Captcha-Bypass", captcha_bypass_secret())
        .form(&[("hashes", "fda95fbeca288d44aad3b435b51404ee")])
        .send()
        .await
        .unwrap();

    assert_success(&resp, "LM case variants");
    let body = resp.text().await.unwrap();

    // All three case variants should appear as full matches under the LM algorithm
    assert_body_contains(
        &body,
        "<td>LM</td><td>hello</td>",
        "LM should find 'hello'",
    );
    assert_body_contains(
        &body,
        "<td>LM</td><td>Hello</td>",
        "LM should find 'Hello'",
    );
    assert_body_contains(
        &body,
        "<td>LM</td><td>HELLO</td>",
        "LM should find 'HELLO'",
    );

    // All matches should be full (green) matches
    let suc_count = body.matches("class=\"suc\"").count();
    assert_eq!(suc_count, 3, "expected exactly 3 success rows for LM case variants, got {}", suc_count);
}

/// Single request with a mix of full match, prefix match, not-found, and format error.
/// All four CSS classes / messages should appear.
#[tokio::test]
async fn mixed_full_prefix_not_found_format_error() {
    let hashes = [
        "5d41402abc4b2a76b9719d911017c592",                                                 // md5("hello") → full match
        "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d",                                         // sha1("hello") → full match
        "d0763edaa9d9bd2a0000000000000000",                                                 // md5("monkey") prefix → partial match
        "0000000000000000000000000000000000000000",                                         // no match → Not found.
        "not-a-hex-hash",                                                                   // invalid → Unrecognized hash format.
    ]
    .join("\n");

    let resp = client()
        .post(url("/"))
        .header("X-Captcha-Bypass", captcha_bypass_secret())
        .form(&[("hashes", hashes.as_str())])
        .send()
        .await
        .unwrap();

    assert_success(&resp, "mixed results");
    let body = resp.text().await.unwrap();

    // Full matches
    assert_body_contains(&body, "class=\"suc\"", "should have full match rows");
    assert_body_contains(
        &body,
        "<td>md5</td><td>hello</td>",
        "md5 should crack 'hello'",
    );
    assert_body_contains(
        &body,
        "<td>sha1</td><td>hello</td>",
        "sha1 should crack 'hello'",
    );

    // Partial match
    assert_body_contains(&body, "class=\"part\"", "should have partial match row");
    assert_body_contains(
        &body,
        "<td>md5</td><td>monkey</td>",
        "md5 prefix should find 'monkey'",
    );

    // Not found
    assert_body_contains(&body, "Not found.", "should show 'Not found.'");

    // Format error
    assert_body_contains(
        &body,
        "Unrecognized hash format.",
        "should show 'Unrecognized hash format.'",
    );
}

/// Submit invalid hashes (too short, non-hex, odd-length) and verify format error message.
#[tokio::test]
async fn unrecognized_hash_format() {
    let hashes = [
        "abcdef0123456",          // too short (13 chars)
        "xyz0000000000000000",    // non-hex characters
        "abcdef01234567890",      // odd length (17 chars)
    ]
    .join("\n");

    let resp = client()
        .post(url("/"))
        .header("X-Captcha-Bypass", captcha_bypass_secret())
        .form(&[("hashes", hashes.as_str())])
        .send()
        .await
        .unwrap();

    assert_success(&resp, "unrecognized format");
    let body = resp.text().await.unwrap();

    // Each invalid hash should produce a format error row
    let format_error_count = body.matches("Unrecognized hash format.").count();
    assert_eq!(
        format_error_count, 3,
        "expected 3 format error rows, got {}",
        format_error_count,
    );

    // All rows should be failures (red)
    assert_body_does_not_contain(&body, "class=\"suc\"", "should not have success rows");
    assert_body_does_not_contain(&body, "class=\"part\"", "should not have partial match rows");
    // "Not found." also appears in the color codes legend, so match the result row markup
    assert_body_does_not_contain(&body, "<td>Not found.</td>", "invalid hashes should not show 'Not found.'");
}

/// Submit a hash for a word that's only in HUGELIST.lst (not REALUNIQ.lst).
/// The md5-huge table should find it even though the regular md5 table can't.
#[tokio::test]
async fn word_only_in_huge_dictionary() {
    // "elephant" is in HUGELIST.lst but NOT in REALUNIQ.lst
    // md5("elephant") = e4b48fd541b3dcb99cababc87c2ee88f
    // sha1("elephant") = 0ae9e4deba26021986ffd99636da6601f6393631
    let hashes = [
        "e4b48fd541b3dcb99cababc87c2ee88f",
        "0ae9e4deba26021986ffd99636da6601f6393631",
    ]
    .join("\n");

    let resp = client()
        .post(url("/"))
        .header("X-Captcha-Bypass", captcha_bypass_secret())
        .form(&[("hashes", hashes.as_str())])
        .send()
        .await
        .unwrap();

    assert_success(&resp, "huge-only word");
    let body = resp.text().await.unwrap();

    // Both should be found via the huge fallback tables
    assert_body_contains(
        &body,
        "<td>md5</td><td>elephant</td>",
        "md5-huge should find 'elephant'",
    );
    assert_body_contains(
        &body,
        "<td>sha1</td><td>elephant</td>",
        "sha1-huge should find 'elephant'",
    );

    let suc_count = body.matches("class=\"suc\"").count();
    assert_eq!(suc_count, 2, "expected 2 success rows for huge-only word, got {}", suc_count);
    assert_body_does_not_contain(&body, "<td>Not found.</td>", "huge-only word should not be 'Not found.'");
}

/// Submit a hash for a word that's only in REALUNIQ.lst (not HUGELIST.lst).
/// The regular md5/sha1 tables should find it.
#[tokio::test]
async fn word_only_in_small_dictionary() {
    // "monkey" is in REALUNIQ.lst but NOT in HUGELIST.lst
    // md5("monkey") = d0763edaa9d9bd2a9516280e9044d885
    // sha1("monkey") = ab87d24bdc7452e55738deb5f868e1f16dea5ace
    let hashes = [
        "d0763edaa9d9bd2a9516280e9044d885",
        "ab87d24bdc7452e55738deb5f868e1f16dea5ace",
    ]
    .join("\n");

    let resp = client()
        .post(url("/"))
        .header("X-Captcha-Bypass", captcha_bypass_secret())
        .form(&[("hashes", hashes.as_str())])
        .send()
        .await
        .unwrap();

    assert_success(&resp, "small-only word");
    let body = resp.text().await.unwrap();

    // Both should be found via the regular (small) tables
    assert_body_contains(
        &body,
        "<td>md5</td><td>monkey</td>",
        "regular md5 should find 'monkey'",
    );
    assert_body_contains(
        &body,
        "<td>sha1</td><td>monkey</td>",
        "regular sha1 should find 'monkey'",
    );

    let suc_count = body.matches("class=\"suc\"").count();
    assert_eq!(suc_count, 2, "expected 2 success rows for small-only word, got {}", suc_count);
    assert_body_does_not_contain(&body, "<td>Not found.</td>", "small-only word should not be 'Not found.'");
}

/// Submit a hash for a word that's in BOTH REALUNIQ.lst and HUGELIST.lst.
/// It should be found exactly once (no duplicate results from both tables).
/// The early_exit logic prevents the md5-huge table from re-matching after
/// the regular md5 table already found a full match.
#[tokio::test]
async fn word_in_both_dictionaries_no_duplicate() {
    // "hello" is in both REALUNIQ.lst and HUGELIST.lst
    // md5("hello") = 5d41402abc4b2a76b9719d911017c592
    // sha1("hello") = aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d
    let hashes = [
        "5d41402abc4b2a76b9719d911017c592",
        "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d",
    ]
    .join("\n");

    let resp = client()
        .post(url("/"))
        .header("X-Captcha-Bypass", captcha_bypass_secret())
        .form(&[("hashes", hashes.as_str())])
        .send()
        .await
        .unwrap();

    assert_success(&resp, "word in both dicts");
    let body = resp.text().await.unwrap();

    // Each hash should produce exactly one md5/sha1 result, not duplicated
    let md5_hello_count = body.matches("<td>md5</td><td>hello</td>").count();
    assert_eq!(
        md5_hello_count, 1,
        "md5('hello') should appear exactly once, not duplicated by md5-huge (got {})",
        md5_hello_count,
    );
    let sha1_hello_count = body.matches("<td>sha1</td><td>hello</td>").count();
    assert_eq!(
        sha1_hello_count, 1,
        "sha1('hello') should appear exactly once, not duplicated by sha1-huge (got {})",
        sha1_hello_count,
    );

    // Exactly 2 success rows total (one per hash)
    let suc_count = body.matches("class=\"suc\"").count();
    assert_eq!(suc_count, 2, "expected 2 success rows (no duplicates), got {}", suc_count);
}

// ===== XSS regression tests =====

/// Submit HTML/script tags as hash input and verify Askama's auto-escaping
/// prevents reflected XSS in both the textarea echo and the results table.
#[tokio::test]
async fn xss_script_tag_escaped_in_textarea_and_results() {
    let xss_payload = "<script>alert('xss')</script>";
    let resp = client()
        .post(url("/"))
        .header("X-Captcha-Bypass", captcha_bypass_secret())
        .form(&[("hashes", xss_payload)])
        .send()
        .await
        .unwrap();

    assert_success(&resp, "XSS script tag");
    let body = resp.text().await.unwrap();

    // The raw <script> tag must NOT appear anywhere in the response
    assert_body_does_not_contain(&body, "<script>alert(", "raw <script> tag must be escaped");

    // The HTML-escaped version must appear (Askama auto-escapes {{ }})
    assert_body_contains(
        &body,
        "&lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt;",
        "script tag should be HTML-escaped",
    );
}

/// Submit quote-heavy and attribute-injection payloads.
#[tokio::test]
async fn xss_quotes_and_attributes_escaped() {
    let xss_payload = "\" onmouseover=\"alert(1)\" x=\"";
    let resp = client()
        .post(url("/"))
        .header("X-Captcha-Bypass", captcha_bypass_secret())
        .form(&[("hashes", xss_payload)])
        .send()
        .await
        .unwrap();

    assert_success(&resp, "XSS attribute injection");
    let body = resp.text().await.unwrap();

    // Raw quotes that could break out of attributes must be escaped
    assert_body_does_not_contain(
        &body,
        "onmouseover=\"alert(1)\"",
        "attribute injection must be escaped",
    );
    assert_body_contains(
        &body,
        "&quot;",
        "double quotes should be HTML-escaped to &quot;",
    );
}

/// Submit a valid hex hash mixed with HTML to ensure the hash column in the
/// results table also escapes properly (not just the textarea).
#[tokio::test]
async fn xss_html_in_hash_column_escaped() {
    // This is valid hex length but contains <img> tag characters — it will
    // fail hash format validation (non-hex chars) and appear in a format
    // error row, which reflects result.hash in the <td>.
    let xss_hash = "<img src=x onerror=alert(1)>";
    let resp = client()
        .post(url("/"))
        .header("X-Captcha-Bypass", captcha_bypass_secret())
        .form(&[("hashes", xss_hash)])
        .send()
        .await
        .unwrap();

    assert_success(&resp, "XSS in hash column");
    let body = resp.text().await.unwrap();

    // The raw <img> tag must not appear
    assert_body_does_not_contain(&body, "<img src=x", "raw <img> tag must be escaped");
    assert_body_contains(
        &body,
        "&lt;img src=x onerror=alert(1)&gt;",
        "<img> should be HTML-escaped in result row",
    );
}

// ===== Input normalization tests =====

/// Submit hashes separated by Windows \r\n line endings.
/// The handler normalizes \r\n to \n before splitting.
#[tokio::test]
async fn input_normalization_windows_line_endings() {
    // md5("password") and md5("hello") separated by \r\n
    let hashes = "5f4dcc3b5aa765d61d8327deb882cf99\r\n5d41402abc4b2a76b9719d911017c592";
    let resp = client()
        .post(url("/"))
        .header("X-Captcha-Bypass", captcha_bypass_secret())
        .form(&[("hashes", hashes)])
        .send()
        .await
        .unwrap();

    assert_success(&resp, "Windows line endings");
    let body = resp.text().await.unwrap();

    // Both hashes should be cracked despite \r\n separator
    assert_body_contains(
        &body,
        "<td>md5</td><td>password</td>",
        "first hash should crack 'password' with \\r\\n separator",
    );
    assert_body_contains(
        &body,
        "<td>md5</td><td>hello</td>",
        "second hash should crack 'hello' with \\r\\n separator",
    );
    let suc_count = body.matches("class=\"suc\"").count();
    assert_eq!(suc_count, 2, "expected 2 success rows with \\r\\n input, got {}", suc_count);
}

/// Submit a bare \r as line separator (old Mac format).
#[tokio::test]
async fn input_normalization_bare_cr() {
    let hashes = "5f4dcc3b5aa765d61d8327deb882cf99\r5d41402abc4b2a76b9719d911017c592";
    let resp = client()
        .post(url("/"))
        .header("X-Captcha-Bypass", captcha_bypass_secret())
        .form(&[("hashes", hashes)])
        .send()
        .await
        .unwrap();

    assert_success(&resp, "bare CR");
    let body = resp.text().await.unwrap();

    assert_body_contains(
        &body,
        "<td>md5</td><td>password</td>",
        "first hash should crack with \\r separator",
    );
    assert_body_contains(
        &body,
        "<td>md5</td><td>hello</td>",
        "second hash should crack with \\r separator",
    );
    let suc_count = body.matches("class=\"suc\"").count();
    assert_eq!(suc_count, 2, "expected 2 success rows with \\r input, got {}", suc_count);
}

/// Submit MySQL 4.1+ hash with surrounding asterisks (*HASH*).
/// The handler strips leading/trailing * before cracking.
#[tokio::test]
async fn input_normalization_mysql_asterisks() {
    // sha1("password") wrapped in asterisks, as MySQL's PASSWORD() function outputs
    let hash_with_asterisks = "*5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8*";
    let resp = client()
        .post(url("/"))
        .header("X-Captcha-Bypass", captcha_bypass_secret())
        .form(&[("hashes", hash_with_asterisks)])
        .send()
        .await
        .unwrap();

    assert_success(&resp, "MySQL asterisks");
    let body = resp.text().await.unwrap();

    assert_body_contains(
        &body,
        "<td>sha1</td><td>password</td>",
        "asterisk-wrapped hash should crack after stripping",
    );
    let suc_count = body.matches("class=\"suc\"").count();
    assert_eq!(suc_count, 1, "expected 1 success row for asterisk-wrapped hash, got {}", suc_count);
}

/// Submit hashes with leading/trailing whitespace.
#[tokio::test]
async fn input_normalization_whitespace_trimming() {
    let hashes = "  5f4dcc3b5aa765d61d8327deb882cf99  \n\t5d41402abc4b2a76b9719d911017c592\t";
    let resp = client()
        .post(url("/"))
        .header("X-Captcha-Bypass", captcha_bypass_secret())
        .form(&[("hashes", hashes)])
        .send()
        .await
        .unwrap();

    assert_success(&resp, "whitespace trimming");
    let body = resp.text().await.unwrap();

    assert_body_contains(
        &body,
        "<td>md5</td><td>password</td>",
        "whitespace-padded hash should crack",
    );
    assert_body_contains(
        &body,
        "<td>md5</td><td>hello</td>",
        "tab-padded hash should crack",
    );
    let suc_count = body.matches("class=\"suc\"").count();
    assert_eq!(suc_count, 2, "expected 2 success rows after whitespace trimming, got {}", suc_count);
}

// ===== Result ordering test =====

/// Submit a mix of hash types in a specific order and verify that result rows
/// appear in the same order as submitted. The cracking core does nontrivial
/// index reconstruction (separating valid/invalid hashes, batching to the oracle,
/// then reassembling in original order) — this test catches ordering bugs.
#[tokio::test]
async fn results_preserve_submission_order() {
    // Submit 5 hashes in a deliberate order mixing all result types:
    //   1. md5("hello")        → full match (suc)
    //   2. "not-a-hex-hash"    → format error (fail)
    //   3. 40 zeroes           → not found (fail)
    //   4. sha1("password")    → full match (suc)
    //   5. md5 prefix monkey   → partial match (part)
    let hash1 = "5d41402abc4b2a76b9719d911017c592";
    let hash2 = "not-a-hex-hash";
    let hash3 = "0000000000000000000000000000000000000000";
    let hash4 = "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8";
    let hash5 = "d0763edaa9d9bd2a0000000000000000";

    let hashes = [hash1, hash2, hash3, hash4, hash5].join("\n");

    let resp = client()
        .post(url("/"))
        .header("X-Captcha-Bypass", captcha_bypass_secret())
        .form(&[("hashes", hashes.as_str())])
        .send()
        .await
        .unwrap();

    assert_success(&resp, "result ordering");
    let body = resp.text().await.unwrap();

    // Extract the portion of the body that contains result rows (between
    // <table class="results"> and </table>) to avoid matching the textarea.
    let table_start = body
        .find("class=\"results\"")
        .expect("results table must be present");
    let table_body = &body[table_start..];

    // Find each hash's position within the results table.
    // The first <td> in each row is the hash itself.
    let pos1 = table_body
        .find(&format!("<td>{}</td>", hash1))
        .unwrap_or_else(|| panic!("hash1 ({}) not found in results table", hash1));
    let pos2 = table_body
        .find(&format!("<td>{}</td>", hash2))
        .unwrap_or_else(|| panic!("hash2 ({}) not found in results table", hash2));
    let pos3 = table_body
        .find(&format!("<td>{}</td>", hash3))
        .unwrap_or_else(|| panic!("hash3 ({}) not found in results table", hash3));
    let pos4 = table_body
        .find(&format!("<td>{}</td>", hash4))
        .unwrap_or_else(|| panic!("hash4 ({}) not found in results table", hash4));
    let pos5 = table_body
        .find(&format!("<td>{}</td>", hash5))
        .unwrap_or_else(|| panic!("hash5 ({}) not found in results table", hash5));

    assert!(
        pos1 < pos2 && pos2 < pos3 && pos3 < pos4 && pos4 < pos5,
        "Result rows must appear in submission order.\n\
         Positions: hash1={}, hash2={}, hash3={}, hash4={}, hash5={}",
        pos1, pos2, pos3, pos4, pos5,
    );
}
