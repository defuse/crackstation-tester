//! Security header tests
//!
//! Every header is compared for an exact value, not a case-insensitive or
//! substring match — a header that drifts to a weaker but similar-looking value
//! is exactly the regression these tests exist to catch.
//!
//! Note that X-Content-Type-Options and Referrer-Policy are additions the port
//! makes over PHP: the live PHP site sends only HSTS (from Caddy), X-Frame-Options,
//! and Content-Type. HSTS itself matches the live site byte for byte.

mod common;

use common::{client, is_production_url, url};

const EXPECTED_X_FRAME_OPTIONS: &str = "SAMEORIGIN";
const EXPECTED_X_CONTENT_TYPE_OPTIONS: &str = "nosniff";
const EXPECTED_REFERRER_POLICY: &str = "strict-origin-when-cross-origin";
const EXPECTED_HSTS: &str = "max-age=31536000; includeSubDomains; preload";

/// Paths covering each routing path: dynamic page, static CSS, static image.
const TEST_PATHS: &[&str] = &[
    "/",
    "/about-us.htm",
    "/css/main.css",
    "/images/crackstation_header.png",
];

/// Read a header as a string, panicking with context if it is absent.
fn header_value(resp: &reqwest::Response, name: &str, context: &str) -> String {
    resp.headers()
        .get(name)
        .unwrap_or_else(|| panic!("{}: {} header is missing", context, name))
        .to_str()
        .unwrap_or_else(|_| panic!("{}: {} header is not valid UTF-8", context, name))
        .to_string()
}

/// Assert the three headers every response must carry, whatever its status.
fn assert_baseline_headers(resp: &reqwest::Response, context: &str) {
    assert_eq!(
        header_value(resp, "x-frame-options", context),
        EXPECTED_X_FRAME_OPTIONS,
        "{}: wrong X-Frame-Options",
        context
    );
    assert_eq!(
        header_value(resp, "x-content-type-options", context),
        EXPECTED_X_CONTENT_TYPE_OPTIONS,
        "{}: wrong X-Content-Type-Options",
        context
    );
    assert_eq!(
        header_value(resp, "referrer-policy", context),
        EXPECTED_REFERRER_POLICY,
        "{}: wrong Referrer-Policy",
        context
    );
}

#[tokio::test]
async fn baseline_headers_on_every_path() {
    for path in TEST_PATHS {
        let resp = client().get(url(path)).send().await.unwrap();
        assert_eq!(
            resp.status().as_u16(),
            200,
            "{} should return 200",
            path
        );
        assert_baseline_headers(&resp, path);
    }
}

/// Headers must survive on non-200 responses too — a redirect or an error page is
/// still a page an attacker can try to frame.
#[tokio::test]
async fn baseline_headers_on_redirect() {
    let resp = client().get(url("/about-us")).send().await.unwrap();
    assert_eq!(resp.status().as_u16(), 301, "/about-us should return 301");
    assert_baseline_headers(&resp, "301 redirect");
}

#[tokio::test]
async fn baseline_headers_on_404() {
    let resp = client()
        .get(url("/nonexistent-page-12345.htm"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 404);
    assert_baseline_headers(&resp, "404 response");
}

#[tokio::test]
async fn baseline_headers_on_405() {
    let resp = client().post(url("/about-us.htm")).send().await.unwrap();
    assert_eq!(resp.status().as_u16(), 405);
    assert_baseline_headers(&resp, "405 response");
}

/// Content-Type is set exactly, and static assets keep their own type rather than
/// being forced to text/html.
#[tokio::test]
async fn content_type_is_exact_per_path() {
    for (path, expected) in [
        ("/", "text/html; charset=utf-8"),
        ("/about-us.htm", "text/html; charset=utf-8"),
        ("/css/main.css", "text/css"),
    ] {
        let resp = client().get(url(path)).send().await.unwrap();
        assert_eq!(
            header_value(&resp, "content-type", path),
            expected,
            "{}: wrong Content-Type",
            path
        );
    }
}

/// HSTS must NOT be sent from a dev host, or a developer's browser would pin
/// localhost to HTTPS and lock them out of the plain-HTTP dev server.
#[tokio::test]
async fn hsts_absent_on_dev_host() {
    if is_production_url() {
        eprintln!("skipping dev-only HSTS absence check against production");
        return;
    }
    for path in TEST_PATHS {
        let resp = client().get(url(path)).send().await.unwrap();
        assert!(
            resp.headers().get("strict-transport-security").is_none(),
            "{}: HSTS must not be sent from a dev host",
            path
        );
    }
}

/// HSTS is only emitted over HTTPS from a non-dev host, so this needs production.
#[tokio::test]
#[ignore = "needs an HTTPS production host; run with CRACKSTATION_URL=https://crackstation.net -- --include-ignored"]
async fn hsts_exact_value_in_production() {
    assert!(
        is_production_url(),
        "hsts_exact_value_in_production requires CRACKSTATION_URL to point at production; \
         a dev host deliberately omits HSTS, so this would verify nothing."
    );

    for path in TEST_PATHS {
        let https_url = url(path).replace("http://", "https://");
        let resp = client().get(&https_url).send().await.unwrap();
        assert_eq!(
            header_value(&resp, "strict-transport-security", path),
            EXPECTED_HSTS,
            "{}: wrong HSTS value",
            path
        );
    }
}
