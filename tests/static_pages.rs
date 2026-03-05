//! Static page smoke tests
//!
//! Verify that all content pages load with 200 OK and contain expected content.

mod common;

use common::{assert_success, client, url, assert_body_contains};

#[tokio::test]
async fn home_page() {
    let resp = client().get(url("/")).send().await.unwrap();
    assert_success(&resp, "home page");
    let body = resp.text().await.unwrap();
    assert_body_contains(&body, "Free Password Hash Cracker", "home page title");
    assert_body_contains(&body, "g-recaptcha", "home page reCAPTCHA");
}

#[tokio::test]
async fn about_page() {
    let resp = client().get(url("/about-us.htm")).send().await.unwrap();
    assert_success(&resp, "about page");
    let body = resp.text().await.unwrap();
    assert_body_contains(&body, "About CrackStation", "about page heading");
}

#[tokio::test]
async fn contact_page() {
    let resp = client().get(url("/contact-us.htm")).send().await.unwrap();
    assert_success(&resp, "contact page");
    let body = resp.text().await.unwrap();
    assert_body_contains(&body, "Contacting CrackStation", "contact page heading");
}

#[tokio::test]
async fn legal_privacy_page() {
    let resp = client()
        .get(url("/legal-privacy.htm"))
        .send()
        .await
        .unwrap();
    assert_success(&resp, "legal/privacy page");
    let body = resp.text().await.unwrap();
    assert_body_contains(
        &body,
        "Terms of Service and Privacy Policy",
        "legal page heading",
    );
}

#[tokio::test]
async fn downloads_page() {
    let resp = client()
        .get(url("/downloads.htm"))
        .send()
        .await
        .unwrap();
    assert_success(&resp, "downloads page");
    let body = resp.text().await.unwrap();
    assert_body_contains(&body, "HashDB", "downloads page content");
}

#[tokio::test]
async fn hashing_security_page() {
    let resp = client()
        .get(url("/hashing-security.htm"))
        .send()
        .await
        .unwrap();
    assert_success(&resp, "hashing-security page");
    let body = resp.text().await.unwrap();
    assert_body_contains(
        &body,
        "Salted Password Hashing",
        "hashing security heading",
    );
}

#[tokio::test]
async fn wordlist_page() {
    let resp = client()
        .get(url("/crackstation-wordlist-password-cracking-dictionary.htm"))
        .send()
        .await
        .unwrap();
    assert_success(&resp, "wordlist page");
    let body = resp.text().await.unwrap();
    assert_body_contains(
        &body,
        "Password Cracking Dictionary",
        "wordlist page heading",
    );
}

#[tokio::test]
async fn thank_you_page() {
    let resp = client()
        .get(url("/thank-you.htm"))
        .send()
        .await
        .unwrap();
    assert_success(&resp, "thank-you page");
    let body = resp.text().await.unwrap();
    assert_body_contains(&body, "THANKS!", "thank-you page heading");
}

/// All pages should have the site navigation menu
#[tokio::test]
async fn all_pages_have_navigation() {
    let pages = &[
        "/",
        "/about-us.htm",
        "/contact-us.htm",
        "/legal-privacy.htm",
        "/downloads.htm",
        "/hashing-security.htm",
        "/crackstation-wordlist-password-cracking-dictionary.htm",
        "/thank-you.htm",
    ];

    for path in pages {
        let resp = client().get(url(path)).send().await.unwrap();
        assert_success(&resp, path);
        let body = resp.text().await.unwrap();
        assert_body_contains(&body, "class=\"menu\"", &format!("{} should have navigation", path));
    }
}

/// All pages should have the footer with hit counter
#[tokio::test]
async fn all_pages_have_footer() {
    let pages = &[
        "/",
        "/about-us.htm",
        "/contact-us.htm",
    ];

    for path in pages {
        let resp = client().get(url(path)).send().await.unwrap();
        assert_success(&resp, path);
        let body = resp.text().await.unwrap();
        assert_body_contains(&body, "Page Hits", &format!("{} should have footer hit counter", path));
    }
}
