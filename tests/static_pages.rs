//! Static page tests
//!
//! Every expected value here comes from the PHP original, not from what the Rust
//! server happens to emit: titles, descriptions, and keywords are transcribed from
//! `$PAGE_INFO` in `crackstation/src/libs/URLParse.php`, and headings from the page
//! files in `crackstation/src/pages/`. Pages that declare no metadata in PHP fall
//! through to the site defaults, so those assert the defaults.

mod common;

use common::{
    client, get_ok, h1, page_meta, url, PageMeta, DEFAULT_DESCRIPTION, DEFAULT_KEYWORDS,
    DEFAULT_TITLE,
};

fn meta(title: &str, description: &str, keywords: &str) -> PageMeta {
    PageMeta {
        title: title.to_string(),
        description: description.to_string(),
        keywords: keywords.to_string(),
    }
}

/// The home page declares no metadata in `$PAGE_INFO`, so it renders the defaults.
#[tokio::test]
async fn home_page() {
    let body = get_ok("/").await;
    assert_eq!(
        page_meta(&body),
        meta(DEFAULT_TITLE, DEFAULT_DESCRIPTION, DEFAULT_KEYWORDS)
    );
    assert_eq!(h1(&body), "Free Password Hash Cracker");
}

/// NOTE: the title really is "CrackStation Contact". PHP's `$PAGE_INFO` entry for
/// about-us copies the contact page's title and keywords; the port reproduces it
/// deliberately, so this asserts the PHP behavior rather than the sensible value.
#[tokio::test]
async fn about_page() {
    let body = get_ok("/about-us.htm").await;
    assert_eq!(
        page_meta(&body),
        meta(
            "CrackStation Contact",
            "What CrackStation is and why we exist",
            "crackstation contact",
        )
    );
    assert_eq!(h1(&body), "About CrackStation");
}

#[tokio::test]
async fn contact_page() {
    let body = get_ok("/contact-us.htm").await;
    assert_eq!(
        page_meta(&body),
        meta(
            "CrackStation Contact",
            "Instructions for contacting CrackStation",
            "crackstation contact",
        )
    );
    assert_eq!(h1(&body), "Contacting CrackStation");
}

#[tokio::test]
async fn legal_privacy_page() {
    let body = get_ok("/legal-privacy.htm").await;
    assert_eq!(
        page_meta(&body),
        meta(
            "CrackStation - Legal and Privacy",
            "CrackStation.net's privacy policy",
            "hash cracking legal, penetration testing, password security",
        )
    );
    assert_eq!(h1(&body), "CrackStation's Terms of Service and Privacy Policy");
}

/// DIVERGENCE FROM PHP (intentional): the downloads page is gone.
///
/// It published four section headings -- HashDB, PHP Cracking Script, Waterfall,
/// Wordlists -- with nothing under any of them, so it was indexable and empty.
#[tokio::test]
async fn downloads_page_is_gone() {
    let resp = client()
        .get(url("/downloads.htm"))
        .send()
        .await
        .expect("request failed");
    assert_eq!(resp.status().as_u16(), 404);
}

#[tokio::test]
async fn hashing_security_page() {
    let body = get_ok("/hashing-security.htm").await;
    assert_eq!(
        page_meta(&body),
        meta(
            "Secure Salted Password Hashing - How to do it Properly",
            "How to hash passwords properly using salt. Why hashes should be salted and how to use salt correctly.",
            "salt, salted hashing, secure password hashing, password hashing, proper way to hash passwords",
        )
    );
    assert_eq!(h1(&body), "Salted Password Hashing - Doing it Right");
}

/// DIVERGENCE FROM PHP (intentional): the unfinished draft article is gone.
///
/// PHP served it at /hashing-security-draft.htm under the *published* article's
/// title, description and keywords, so search engines saw two URLs claiming to be
/// the same page and the draft could outrank the finished one. Nothing linked to
/// it. It is now a 404.
#[tokio::test]
async fn hashing_security_draft_is_gone() {
    let resp = client()
        .get(url("/hashing-security-draft.htm"))
        .send()
        .await
        .expect("request failed");
    assert_eq!(resp.status().as_u16(), 404);
}

#[tokio::test]
async fn wordlist_page() {
    let body = get_ok("/crackstation-wordlist-password-cracking-dictionary.htm").await;
    assert_eq!(
        page_meta(&body),
        meta(
            "CrackStation's Password Cracking Dictionary (Pay what you want!)",
            "Download CrackStation's password cracking wordlist.",
            "password cracking wordlist, biggest password cracking wordlist, cracking dictionary",
        )
    );
    assert_eq!(h1(&body), "CrackStation's Password Cracking Dictionary");
}

/// DIVERGENCE FROM PHP (intentional): the thank-you page is gone.
///
/// It confirmed a donation that could not have happened -- the flow that once
/// reached it was removed, and nothing on the site links to it -- so anyone who
/// found the URL was told "THANKS!" for a purchase they never made.
#[tokio::test]
async fn thank_you_page_is_gone() {
    let resp = client()
        .get(url("/thank-you.htm"))
        .send()
        .await
        .expect("request failed");
    assert_eq!(resp.status().as_u16(), 404);
}

/// Every page carries the shared navigation and the footer hit counter.
#[tokio::test]
async fn every_page_has_navigation_and_footer() {
    let pages = [
        "/",
        "/about-us.htm",
        "/contact-us.htm",
        "/legal-privacy.htm",
        "/hashing-security.htm",
        "/crackstation-wordlist-password-cracking-dictionary.htm",
    ];

    for path in pages {
        let body = get_ok(path).await;
        assert_eq!(
            body.matches("class=\"menu\"").count(),
            1,
            "{} should have exactly one navigation menu",
            path
        );
        assert!(
            body.contains("Page Hits"),
            "{} should have the footer hit counter",
            path
        );
    }
}

/// The reCAPTCHA widget and its script belong on the home page only — PHP emits the
/// api.js tag solely when the page name is "".
#[tokio::test]
async fn recaptcha_only_on_home_page() {
    let home = get_ok("/").await;
    assert_eq!(
        home.matches("g-recaptcha").count(),
        1,
        "home page should have exactly one reCAPTCHA widget"
    );
    assert!(
        home.contains("https://www.google.com/recaptcha/api.js"),
        "home page should load the reCAPTCHA script"
    );

    for path in ["/about-us.htm", "/contact-us.htm", "/legal-privacy.htm"] {
        let body = get_ok(path).await;
        assert!(
            !body.contains("recaptcha/api.js"),
            "{} should not load the reCAPTCHA script",
            path
        );
    }
}

/// A GET to a page must not increment anything or vary: two fetches of the same
/// page return identical metadata.
#[tokio::test]
async fn page_rendering_is_stable_across_requests() {
    let first = get_ok("/about-us.htm").await;
    let second = get_ok("/about-us.htm").await;
    assert_eq!(page_meta(&first), page_meta(&second));
    assert_eq!(h1(&first), h1(&second));
}

/// POSTing to a content page is not allowed — only the home page accepts POST.
///
/// DIVERGENCE FROM PHP (intentional): PHP ignores the request method and renders
/// the page with 200. The port answers 405, which is the correct HTTP response and
/// matches defuse-rust's dispatcher.
#[tokio::test]
async fn post_to_content_page_is_rejected() {
    let resp = client()
        .post(url("/about-us.htm"))
        .form(&[("hashes", "5f4dcc3b5aa765d61d8327deb882cf99")])
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        405,
        "POST to a content page should be 405 Method Not Allowed"
    );
}
