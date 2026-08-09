//! Error page tests
//!
//! The 404 body is transcribed from `crackstation/src/pages/404.php`, and its
//! metadata is the site default — PHP's `$FILE_NOT_FOUND[P_TITL]` of "File Not
//! Found" is dead code, because `ProcessURL()` returns the string "404", which is
//! not a `$PAGE_INFO` key, so `getPageTitle()` falls through to `$DEFAULT_TITLE`.
//! Verified against the live PHP site.

mod common;

use common::{
    client, h1, page_meta, url, PageMeta, DEFAULT_DESCRIPTION, DEFAULT_KEYWORDS, DEFAULT_TITLE,
};

const MISSING_PAGE: &str = "/nonexistent-page-12345.htm";

async fn fetch_404() -> String {
    let resp = client().get(url(MISSING_PAGE)).send().await.unwrap();
    assert_eq!(
        resp.status().as_u16(),
        404,
        "{} should return 404",
        MISSING_PAGE
    );
    resp.text().await.unwrap()
}

#[tokio::test]
async fn not_found_returns_404_status() {
    let resp = client().get(url(MISSING_PAGE)).send().await.unwrap();
    assert_eq!(resp.status().as_u16(), 404);
}

/// The 404 page renders the site defaults, matching the live PHP site.
#[tokio::test]
async fn not_found_page_uses_default_metadata() {
    let body = fetch_404().await;
    assert_eq!(
        page_meta(&body),
        PageMeta {
            title: DEFAULT_TITLE.to_string(),
            description: DEFAULT_DESCRIPTION.to_string(),
            keywords: DEFAULT_KEYWORDS.to_string(),
        }
    );
}

/// Exact body text from 404.php: "Oops!", the explanation, the divide-by-zero
/// image, and the error code.
#[tokio::test]
async fn not_found_page_has_expected_content() {
    let body = fetch_404().await;

    for fragment in [
        ">Oops!<",
        ">This page does not exist.<",
        "/images/divzero.png",
        ">(ERROR 404)<",
    ] {
        assert!(
            body.contains(fragment),
            "404 page should contain {:?}",
            fragment
        );
    }

    // 404.php uses styled spans, not a heading.
    assert_eq!(
        body.matches("<h1").count(),
        0,
        "the 404 page has no <h1> in the PHP original"
    );
}

/// The 404 page is a full site page, not a bare error: it keeps the navigation
/// and the footer hit counter.
#[tokio::test]
async fn not_found_page_is_a_full_site_page() {
    let body = fetch_404().await;
    assert_eq!(
        body.matches("class=\"menu\"").count(),
        1,
        "404 page should have exactly one navigation menu"
    );
    assert!(
        body.contains("Page Hits"),
        "404 page should have the footer hit counter"
    );
}

/// A 404 must not leak the crack form — only the home page has one.
#[tokio::test]
async fn not_found_page_has_no_crack_form() {
    let body = fetch_404().await;
    assert!(
        !body.contains("name=\"hashes\""),
        "404 page should not render the hash submission form"
    );
    assert!(
        !body.contains("table class=\"results\""),
        "404 page should not render a results table"
    );
}

/// DIVERGENCE FROM PHP (intentional): PHP ignores the request method and serves
/// the page with 200; the port answers 405.
#[tokio::test]
async fn post_to_static_page_returns_405() {
    let resp = client().post(url("/about-us.htm")).send().await.unwrap();
    assert_eq!(
        resp.status().as_u16(),
        405,
        "POST to /about-us.htm should return 405"
    );
}

/// The 404 handler is reached by several routing paths; all must render the same
/// page, not just the .htm one.
#[tokio::test]
async fn all_404_routes_render_the_same_page() {
    let canonical = fetch_404().await;
    let canonical_meta = page_meta(&canonical);

    for path in ["/nonexistent-page-12345", "/about-us/", "/.htm"] {
        let resp = client().get(url(path)).send().await.unwrap();
        assert_eq!(resp.status().as_u16(), 404, "{} should return 404", path);
        let body = resp.text().await.unwrap();
        assert_eq!(page_meta(&body), canonical_meta, "{} metadata differs", path);
        assert!(
            body.contains(">This page does not exist.<"),
            "{} should render the 404 body",
            path
        );
    }
}

/// Guard against `h1()` silently succeeding on a page with no heading.
#[tokio::test]
#[should_panic(expected = "expected exactly one <h1>")]
async fn h1_helper_rejects_pages_without_a_heading() {
    let body = fetch_404().await;
    let _ = h1(&body);
}
