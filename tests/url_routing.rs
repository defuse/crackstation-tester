//! URL routing and canonicalization tests
//!
//! Tests for URL normalization, extension handling, and alias redirects.

mod common;

use common::{assert_redirect, assert_success, client, url};

// =============================================================================
// Extension & Case Normalization
// =============================================================================

/// No extension redirects to .htm
#[tokio::test]
async fn no_extension_redirects_to_htm() {
    let resp = client().get(url("/about-us")).send().await.unwrap();
    assert_redirect(&resp, &url("/about-us.htm"), "/about-us -> /about-us.htm");
}

/// .html redirects to .htm
#[tokio::test]
async fn html_redirects_to_htm() {
    let resp = client().get(url("/about-us.html")).send().await.unwrap();
    assert_redirect(
        &resp,
        &url("/about-us.htm"),
        "/about-us.html -> /about-us.htm",
    );
}

/// Uppercase .HTM redirects to lowercase
#[tokio::test]
async fn uppercase_htm_redirects() {
    let resp = client().get(url("/about-us.HTM")).send().await.unwrap();
    assert_redirect(
        &resp,
        &url("/about-us.htm"),
        "/about-us.HTM -> /about-us.htm",
    );
}

/// Mixed case page name redirects to lowercase
#[tokio::test]
async fn mixed_case_redirects() {
    let resp = client().get(url("/About-Us.htm")).send().await.unwrap();
    assert_redirect(
        &resp,
        &url("/about-us.htm"),
        "/About-Us.htm -> /about-us.htm",
    );
}

/// All-uppercase redirects to lowercase
#[tokio::test]
async fn all_uppercase_redirects() {
    let resp = client().get(url("/ABOUT-US.HTM")).send().await.unwrap();
    assert_redirect(
        &resp,
        &url("/about-us.htm"),
        "/ABOUT-US.HTM -> /about-us.htm",
    );
}

/// Canonical .htm URL returns 200 (no redirect)
#[tokio::test]
async fn canonical_htm_no_redirect() {
    let resp = client().get(url("/about-us.htm")).send().await.unwrap();
    assert_success(&resp, "/about-us.htm should return 200");
}

/// Root URL returns 200 (no redirect)
#[tokio::test]
async fn root_no_redirect() {
    let resp = client().get(url("/")).send().await.unwrap();
    assert_success(&resp, "/ should return 200");
}

// =============================================================================
// Index/Home Redirects
// =============================================================================

/// /index redirects to /
#[tokio::test]
async fn index_redirects_to_root() {
    let resp = client().get(url("/index")).send().await.unwrap();
    assert_redirect(&resp, &url("/"), "/index -> /");
}

/// /index.htm redirects to /
#[tokio::test]
async fn index_htm_redirects_to_root() {
    let resp = client().get(url("/index.htm")).send().await.unwrap();
    assert_redirect(&resp, &url("/"), "/index.htm -> /");
}

/// /index.html redirects to /
#[tokio::test]
async fn index_html_redirects_to_root() {
    let resp = client().get(url("/index.html")).send().await.unwrap();
    assert_redirect(&resp, &url("/"), "/index.html -> /");
}

/// /index.php redirects to /
#[tokio::test]
async fn index_php_redirects_to_root() {
    let resp = client().get(url("/index.php")).send().await.unwrap();
    assert_redirect(&resp, &url("/"), "/index.php -> /");
}

// =============================================================================
// 404 for Unknown Pages
// =============================================================================

/// Unknown page returns 404
#[tokio::test]
async fn unknown_page_returns_404() {
    let resp = client()
        .get(url("/nonexistent-page-12345.htm"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        404,
        "/nonexistent-page-12345.htm should return 404"
    );
}

/// Unknown page without extension returns 404
#[tokio::test]
async fn unknown_page_no_extension_returns_404() {
    let resp = client()
        .get(url("/nonexistent-page-12345"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        404,
        "/nonexistent-page-12345 should return 404"
    );
}

/// Trailing slash on non-root path returns 404
#[tokio::test]
async fn trailing_slash_returns_404() {
    let resp = client()
        .get(url("/about-us/"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        404,
        "/about-us/ should return 404"
    );
}

/// Bare .htm returns 404
#[tokio::test]
async fn bare_htm_returns_404() {
    let resp = client().get(url("/.htm")).send().await.unwrap();
    assert_eq!(resp.status().as_u16(), 404, "/.htm should return 404");
}

// =============================================================================
// All canonical page URLs return 200
// =============================================================================

/// Every registered page's canonical URL returns 200
#[tokio::test]
async fn all_canonical_pages_return_200() {
    let canonical_pages = &[
        "/",
        "/about-us.htm",
        "/contact-us.htm",
        "/legal-privacy.htm",
        "/downloads.htm",
        "/hashing-security.htm",
        "/crackstation-wordlist-password-cracking-dictionary.htm",
        "/thank-you.htm",
    ];

    for path in canonical_pages {
        let resp = client().get(url(path)).send().await.unwrap();
        assert_success(&resp, &format!("{} should return 200", path));
    }
}
