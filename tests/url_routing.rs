//! URL routing and canonicalization tests
//!
//! Every redirect asserts an exact 301 and an exact Location, and every canonical
//! URL asserts exactly 200 with no Location header at all.
//!
//! Expectations come from `$PAGE_INFO` and `ensureHTMOrSlashExtension()` in
//! `crackstation/src/libs/URLParse.php`, except where the port deliberately
//! improves on PHP — those cases are called out individually, because PHP's live
//! behavior there is a bug we chose not to reproduce.

mod common;

use common::{assert_redirect, client, url};

/// Assert a path is served directly: exactly 200, and no Location header.
async fn assert_no_redirect(path: &str) {
    let resp = client().get(url(path)).send().await.unwrap();
    assert_eq!(
        resp.status().as_u16(),
        200,
        "{} should be served directly with 200",
        path
    );
    assert!(
        resp.headers().get("location").is_none(),
        "{} should not send a Location header",
        path
    );
}

/// Assert a path 404s.
async fn assert_not_found(path: &str) {
    let resp = client().get(url(path)).send().await.unwrap();
    assert_eq!(resp.status().as_u16(), 404, "{} should return 404", path);
}

// =============================================================================
// Extension canonicalization
// =============================================================================

/// PHP's ensureHTMOrSlashExtension() appends .htm to any bare page name.
#[tokio::test]
async fn no_extension_redirects_to_htm() {
    let resp = client().get(url("/about-us")).send().await.unwrap();
    assert_redirect(&resp, &url("/about-us.htm"), "/about-us -> /about-us.htm");
}

/// PHP preserves the query string across the canonicalizing redirect
/// (getUrlParams() is appended to every permRedirect target).
#[tokio::test]
async fn redirect_preserves_query_string() {
    let resp = client().get(url("/about-us?foo=bar")).send().await.unwrap();
    assert_redirect(
        &resp,
        &url("/about-us.htm?foo=bar"),
        "/about-us?foo=bar -> /about-us.htm?foo=bar",
    );
}

/// `.html` spellings that PHP lists explicitly in $PAGE_INFO.
#[tokio::test]
async fn explicit_html_aliases_redirect_to_htm() {
    for (from, to) in [
        ("/hashing-security.html", "/hashing-security.htm"),
        ("/legal-privacy.html", "/legal-privacy.htm"),
    ] {
        let resp = client().get(url(from)).send().await.unwrap();
        assert_redirect(&resp, &url(to), from);
    }
}

/// DIVERGENCE FROM PHP (intentional): PHP only redirects the handful of `.html`
/// spellings hardcoded in $PAGE_INFO, so `/about-us.html` is a 404 on the live
/// site. The port applies the rule to every page instead.
#[tokio::test]
async fn html_redirects_to_htm_for_any_page() {
    let resp = client().get(url("/about-us.html")).send().await.unwrap();
    assert_redirect(
        &resp,
        &url("/about-us.htm"),
        "/about-us.html -> /about-us.htm",
    );
}

/// DIVERGENCE FROM PHP (intentional): PHP looks pages up case-insensitively but
/// then tests the raw path with a case-sensitive strpos($file, ".htm"), so an
/// uppercase extension is not recognized and `.htm` gets appended a second time —
/// the live site sends `/ABOUT-US.HTM` to `/ABOUT-US.HTM.htm`, which then 404s.
/// `/About-Us.htm` is served at its non-canonical URL rather than redirected.
/// The port canonicalizes case instead.
#[tokio::test]
async fn case_variants_redirect_to_canonical_lowercase() {
    for from in ["/about-us.HTM", "/About-Us.htm", "/ABOUT-US.HTM", "/AbOuT-uS"] {
        let resp = client().get(url(from)).send().await.unwrap();
        assert_redirect(&resp, &url("/about-us.htm"), from);
    }
}

// =============================================================================
// Aliases
// =============================================================================

/// All four index spellings collapse to the site root.
#[tokio::test]
async fn index_spellings_redirect_to_root() {
    for from in ["/index", "/index.htm", "/index.html", "/index.php"] {
        let resp = client().get(url(from)).send().await.unwrap();
        assert_redirect(&resp, &url("/"), from);
    }
}

#[tokio::test]
async fn index_redirect_preserves_query_string() {
    let resp = client().get(url("/index?x=1")).send().await.unwrap();
    assert_redirect(&resp, &url("/?x=1"), "/index?x=1 -> /?x=1");
}

/// The legacy wordlist URL, still 301'd by the live PHP site.
#[tokio::test]
async fn legacy_wordlist_url_redirects() {
    for from in [
        "/buy-crackstation-wordlist-password-cracking-dictionary",
        "/buy-crackstation-wordlist-password-cracking-dictionary.htm",
    ] {
        let resp = client().get(url(from)).send().await.unwrap();
        assert_redirect(
            &resp,
            &url("/crackstation-wordlist-password-cracking-dictionary.htm"),
            from,
        );
    }
}

// =============================================================================
// Canonical URLs are served directly
// =============================================================================

#[tokio::test]
async fn canonical_urls_are_not_redirected() {
    for path in [
        "/",
        "/about-us.htm",
        "/contact-us.htm",
        "/legal-privacy.htm",
        "/downloads.htm",
        "/hashing-security.htm",
        "/hashing-security-draft.htm",
        "/crackstation-wordlist-password-cracking-dictionary.htm",
        "/thank-you.htm",
    ] {
        assert_no_redirect(path).await;
    }
}

// =============================================================================
// 404s
// =============================================================================

#[tokio::test]
async fn unknown_pages_return_404() {
    for path in [
        "/nonexistent-page-12345.htm",
        "/nonexistent-page-12345",
        "/nonexistent-page-12345.html",
    ] {
        assert_not_found(path).await;
    }
}

/// CrackStation has no virtual directories, so a trailing slash never resolves.
/// PHP rejects `/.htm` and `/foo/.htm` in getPageArrayKey() for the same reason.
///
/// DIVERGENCE FROM PHP (intentional): the live site answers `/.htm` and `/.html`
/// with 403, not 404 — that comes from the front-end web server refusing
/// dotfile-looking paths, not from URLParse, which would return false and 404.
/// The port answers 404, which also leaks slightly less.
#[tokio::test]
async fn trailing_slash_and_bare_extension_return_404() {
    for path in ["/about-us/", "/.htm", "/.html"] {
        assert_not_found(path).await;
    }
}

/// DIVERGENCE FROM PHP (intentional): these two names are in PHP's $PAGE_INFO but
/// their .php files do not exist, so IncludePageContents() falls back to 404.php
/// while send404Headers() is never called — the live site returns HTTP 200 with
/// the page's own title and the 404 body. The port returns an honest 404.
#[tokio::test]
async fn pages_with_no_content_file_return_404() {
    for path in ["/cracking-services.htm", "/how-crackstation-works.htm"] {
        assert_not_found(path).await;
    }
}
