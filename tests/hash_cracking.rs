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
