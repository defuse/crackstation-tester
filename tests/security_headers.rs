//! Security header tests
//!
//! Tests for security-related HTTP headers across all route types.

mod common;

use common::{client, is_production_url, url};

/// All paths to test - covers different routing logic paths
const TEST_PATHS: &[&str] = &[
    "/",                                                          // Home page (dynamic)
    "/about-us.htm",                                              // Regular page (dynamic)
    "/css/main.css",                                              // Static CSS
    "/images/crackstation_header.png",                            // Static image
];

// =============================================================================
// X-Frame-Options
// =============================================================================

/// X-Frame-Options should be SAMEORIGIN on all paths
#[tokio::test]
async fn x_frame_options_on_all_paths() {
    for path in TEST_PATHS {
        let resp = client().get(url(path)).send().await.unwrap();
        assert!(
            resp.status().is_success(),
            "{} should return 200, got {}",
            path,
            resp.status()
        );

        let header = resp
            .headers()
            .get("x-frame-options")
            .unwrap_or_else(|| panic!("X-Frame-Options missing on {}", path))
            .to_str()
            .unwrap();

        assert_eq!(
            header.to_uppercase(),
            "SAMEORIGIN",
            "X-Frame-Options should be SAMEORIGIN on {}, got: {}",
            path,
            header
        );
    }
}

// =============================================================================
// HSTS (production HTTPS only)
// =============================================================================

/// HSTS should be present on all paths over HTTPS
#[tokio::test]
async fn hsts_on_all_paths() {
    if !is_production_url() {
        eprintln!("Skipping HSTS test on local URL");
        return;
    }

    for path in TEST_PATHS {
        let https_url = url(path).replace("http://", "https://");
        let resp = client().get(&https_url).send().await.unwrap();

        let header = resp
            .headers()
            .get("strict-transport-security")
            .unwrap_or_else(|| panic!("HSTS missing on {}", path))
            .to_str()
            .unwrap();

        assert!(
            header.contains("max-age="),
            "HSTS should have max-age on {}, got: {}",
            path,
            header
        );
    }
}

// =============================================================================
// X-Content-Type-Options
// =============================================================================

/// X-Content-Type-Options: nosniff on all paths
#[tokio::test]
async fn x_content_type_options_on_all_paths() {
    for path in TEST_PATHS {
        let resp = client().get(url(path)).send().await.unwrap();
        assert!(
            resp.status().is_success(),
            "{} should return 200, got {}",
            path,
            resp.status()
        );

        let header = resp
            .headers()
            .get("x-content-type-options")
            .unwrap_or_else(|| panic!("X-Content-Type-Options missing on {}", path))
            .to_str()
            .unwrap();

        assert_eq!(
            header.to_lowercase(),
            "nosniff",
            "X-Content-Type-Options should be nosniff on {}, got: {}",
            path,
            header
        );
    }
}

// =============================================================================
// Referrer-Policy
// =============================================================================

/// Referrer-Policy on all paths
#[tokio::test]
async fn referrer_policy_on_all_paths() {
    for path in TEST_PATHS {
        let resp = client().get(url(path)).send().await.unwrap();
        assert!(
            resp.status().is_success(),
            "{} should return 200, got {}",
            path,
            resp.status()
        );

        let header = resp
            .headers()
            .get("referrer-policy")
            .unwrap_or_else(|| panic!("Referrer-Policy missing on {}", path))
            .to_str()
            .unwrap();

        assert_eq!(
            header, "strict-origin-when-cross-origin",
            "Referrer-Policy should be strict-origin-when-cross-origin on {}, got: {}",
            path,
            header
        );
    }
}

// =============================================================================
// Security Headers on Redirect Responses
// =============================================================================

/// 301 redirect responses should carry security headers
#[tokio::test]
async fn security_headers_on_301_redirect() {
    let resp = client().get(url("/about-us")).send().await.unwrap();
    assert_eq!(
        resp.status().as_u16(),
        301,
        "/about-us should return 301"
    );

    let headers = resp.headers();

    let xfo = headers
        .get("x-frame-options")
        .expect("301 redirect should have X-Frame-Options")
        .to_str()
        .unwrap();
    assert_eq!(
        xfo.to_uppercase(),
        "SAMEORIGIN",
        "301 redirect should have X-Frame-Options: SAMEORIGIN, got: {}",
        xfo
    );

    let xcto = headers
        .get("x-content-type-options")
        .expect("301 redirect should have X-Content-Type-Options")
        .to_str()
        .unwrap();
    assert_eq!(
        xcto.to_lowercase(),
        "nosniff",
        "301 redirect should have X-Content-Type-Options: nosniff, got: {}",
        xcto
    );

    let rp = headers
        .get("referrer-policy")
        .expect("301 redirect should have Referrer-Policy")
        .to_str()
        .unwrap();
    assert_eq!(
        rp, "strict-origin-when-cross-origin",
        "301 redirect should have Referrer-Policy: strict-origin-when-cross-origin, got: {}",
        rp
    );
}

// =============================================================================
// Security Headers on Error Responses
// =============================================================================

/// 404 error pages should carry security headers
#[tokio::test]
async fn security_headers_on_404() {
    let resp = client()
        .get(url("/nonexistent-page-12345.htm"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 404, "Should return 404");

    let headers = resp.headers();
    assert_eq!(
        headers
            .get("x-frame-options")
            .expect("404 should have X-Frame-Options")
            .to_str()
            .unwrap()
            .to_uppercase(),
        "SAMEORIGIN",
        "404 should have X-Frame-Options: SAMEORIGIN"
    );
    assert_eq!(
        headers
            .get("x-content-type-options")
            .expect("404 should have X-Content-Type-Options")
            .to_str()
            .unwrap()
            .to_lowercase(),
        "nosniff",
        "404 should have X-Content-Type-Options: nosniff"
    );
    assert_eq!(
        headers
            .get("referrer-policy")
            .expect("404 should have Referrer-Policy")
            .to_str()
            .unwrap(),
        "strict-origin-when-cross-origin",
        "404 should have Referrer-Policy: strict-origin-when-cross-origin"
    );
}
