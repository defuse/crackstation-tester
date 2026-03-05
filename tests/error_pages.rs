//! Error page tests
//!
//! Tests for 404 and other error pages.

mod common;

use common::{assert_body_contains, assert_status, client, url};

// =============================================================================
// 404 Status
// =============================================================================

/// Nonexistent page returns 404 status
#[tokio::test]
async fn returns_404_status() {
    let resp = client()
        .get(url("/nonexistent-page-12345.htm"))
        .send()
        .await
        .unwrap();
    assert_status(&resp, 404, "/nonexistent-page-12345.htm should return 404");
}

// =============================================================================
// 404 Page Content
// =============================================================================

/// 404 page contains error message text
#[tokio::test]
async fn has_expected_content() {
    let resp = client()
        .get(url("/nonexistent-page-12345.htm"))
        .send()
        .await
        .unwrap();
    let body = resp.text().await.unwrap();

    assert_body_contains(&body, "404", "404 page should mention '404'");
    assert_body_contains(
        &body,
        "does not exist",
        "404 page should say 'does not exist'",
    );
}

/// 404 page has site navigation (not a bare error page)
#[tokio::test]
async fn has_navigation() {
    let resp = client()
        .get(url("/nonexistent-page-12345.htm"))
        .send()
        .await
        .unwrap();
    let body = resp.text().await.unwrap();

    assert_body_contains(
        &body,
        "class=\"menu\"",
        "404 page should have site navigation menu",
    );
}

// =============================================================================
// Method Not Allowed
// =============================================================================

/// POST to a page that doesn't accept POST returns 405
#[tokio::test]
async fn post_to_static_page_returns_405() {
    let resp = client()
        .post(url("/about-us.htm"))
        .send()
        .await
        .unwrap();
    assert_status(&resp, 405, "POST to /about-us.htm should return 405");
}
