//! Hash cracking tests
//!
//! Tests for the hash cracking form and results.
//! All POST tests use the X-Captcha-Bypass header to skip reCAPTCHA.

mod common;

use common::{
    assert_body_contains, assert_body_does_not_contain, assert_success, client,
    captcha_bypass_secret, url,
};

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

/// POST without captcha bypass or valid token should fail.
#[tokio::test]
async fn no_captcha_fails() {
    let resp = client()
        .post(url("/"))
        .form(&[("hashes", "5f4dcc3b5aa765d61d8327deb882cf99")])
        .send()
        .await
        .unwrap();

    assert_success(&resp, "no captcha");
    let body = resp.text().await.unwrap();
    assert_body_contains(&body, "captcha", "should show captcha error");
}

/// Wrong captcha bypass secret should fail.
#[tokio::test]
async fn wrong_bypass_secret_fails() {
    let resp = client()
        .post(url("/"))
        .header("X-Captcha-Bypass", "wrong-secret-value")
        .form(&[("hashes", "5f4dcc3b5aa765d61d8327deb882cf99")])
        .send()
        .await
        .unwrap();

    assert_success(&resp, "wrong bypass secret");
    let body = resp.text().await.unwrap();
    assert_body_contains(&body, "captcha", "should show captcha error");
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

    // No failures or format errors
    assert_body_does_not_contain(&body, "Not found.", "no hash should be 'Not found.'");
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

    // No full matches (the suffixes are wrong)
    assert_body_does_not_contain(&body, "class=\"suc\"", "should not have full match rows");
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
    assert_body_does_not_contain(&body, "Not found.", "invalid hashes should not show 'Not found.'");
}
