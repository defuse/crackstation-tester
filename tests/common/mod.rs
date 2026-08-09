//! Shared test utilities for crackstation-tester
//!
//! Provides HTTP client, base URL configuration, and common assertions.

use reqwest::Client;

/// Create a new HTTP client for testing.
/// - Does NOT follow redirects automatically (so we can test redirect behavior)
/// - Has reasonable timeouts
pub fn client() -> Client {
    Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .expect("Failed to create HTTP client")
}

/// Derive the Origin header value (scheme + host) from CRACKSTATION_URL.
pub fn origin() -> String {
    let base = base_url();
    if let Some(scheme_end) = base.find("://") {
        let after_scheme = &base[scheme_end + 3..];
        let host_end = after_scheme.find('/').unwrap_or(after_scheme.len());
        base[..scheme_end + 3 + host_end].to_string()
    } else {
        base
    }
}

/// Get the base URL to test against.
/// CRACKSTATION_URL environment variable must be set.
pub fn base_url() -> String {
    std::env::var("CRACKSTATION_URL").expect("CRACKSTATION_URL environment variable must be set")
}

/// Get the captcha bypass key for hash cracking tests.
/// Reads from secrets/captcha-bypass-key.txt (gitignored).
pub fn captcha_bypass_secret() -> String {
    let secrets_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("secrets");
    let key_file = secrets_dir.join("captcha-bypass-key.txt");
    std::fs::read_to_string(&key_file)
        .unwrap_or_else(|e| panic!(
            "Failed to read captcha bypass key from {}: {}. \
             Generate it with: xxd -l 32 -p /dev/urandom | tr -d '\\n' > {}",
            key_file.display(), e, key_file.display()
        ))
        .trim()
        .to_string()
}

/// Check if tests are running against a local URL (localhost, 127.0.0.1, ::1).
pub fn is_local_url() -> bool {
    let base = base_url().to_lowercase();
    base.contains("localhost")
        || base.contains("127.0.0.1")
        || base.contains("[::1]")
        || base.contains("0.0.0.0")
}

/// Check if tests are running against a production URL (not local).
pub fn is_production_url() -> bool {
    !is_local_url()
}

/// Build a full URL from a path
pub fn url(path: &str) -> String {
    let base = base_url();
    let base = base.trim_end_matches('/');
    if path.starts_with('/') {
        format!("{}{}", base, path)
    } else {
        format!("{}/{}", base, path)
    }
}

/// Assert that a response has a successful status code (2xx)
pub fn assert_success(response: &reqwest::Response, context: &str) {
    assert!(
        response.status().is_success(),
        "{}: expected 2xx status, got {}",
        context,
        response.status()
    );
}

/// Assert that a response has a specific status code
pub fn assert_status(response: &reqwest::Response, expected: u16, context: &str) {
    assert_eq!(
        response.status().as_u16(),
        expected,
        "{}: expected status {}, got {}",
        context,
        expected,
        response.status()
    );
}

/// Assert that a response has the expected content-type (prefix match)
pub fn assert_content_type(response: &reqwest::Response, expected_prefix: &str, context: &str) {
    let content_type = response
        .headers()
        .get("content-type")
        .unwrap_or_else(|| panic!("{}: missing content-type header", context))
        .to_str()
        .unwrap_or_else(|_| panic!("{}: invalid content-type header", context));

    assert!(
        content_type.starts_with(expected_prefix),
        "{}: expected content-type starting with '{}', got '{}'",
        context,
        expected_prefix,
        content_type
    );
}

/// Assert that a header exists and has the expected value
pub fn assert_header(response: &reqwest::Response, header: &str, expected: &str, context: &str) {
    let value = response
        .headers()
        .get(header)
        .unwrap_or_else(|| panic!("{}: missing {} header", context, header))
        .to_str()
        .unwrap_or_else(|_| panic!("{}: invalid {} header value", context, header));

    assert_eq!(
        value, expected,
        "{}: expected {} header to be '{}', got '{}'",
        context, header, expected, value
    );
}

/// Assert that HTML body contains expected text
pub fn assert_body_contains(body: &str, needle: &str, context: &str) {
    assert!(
        body.contains(needle),
        "{}: expected body to contain '{}', but it didn't.\nBody preview: {}...",
        context,
        needle,
        &body.chars().take(500).collect::<String>()
    );
}

/// Assert that HTML body does NOT contain text
pub fn assert_body_does_not_contain(body: &str, needle: &str, context: &str) {
    assert!(
        !body.contains(needle),
        "{}: expected body NOT to contain '{}', but it did.\nBody preview: {}...",
        context,
        needle,
        &body.chars().take(500).collect::<String>()
    );
}

/// Assert that a response is a 301 redirect to the expected location.
pub fn assert_redirect(response: &reqwest::Response, expected_location: &str, context: &str) {
    assert_eq!(
        response.status().as_u16(),
        301,
        "{}: expected 301 redirect, got {}",
        context,
        response.status()
    );

    let location = response
        .headers()
        .get("location")
        .unwrap_or_else(|| panic!("{}: missing Location header on redirect", context))
        .to_str()
        .unwrap_or_else(|_| panic!("{}: invalid Location header value", context));

    // RFC 7231 allows a relative Location, and PHP emits one ("/about-us.htm")
    // where the Rust server emits an absolute URL. Both send a browser to the same
    // place, so compare the resolved target rather than the encoding — that keeps
    // these assertions meaningful against either implementation.
    let resolved = if location.starts_with('/') {
        format!("{}{}", origin(), location)
    } else {
        location.to_string()
    };

    assert_eq!(
        resolved, expected_location,
        "{}: expected redirect to '{}', got '{}'",
        context, expected_location, location
    );
}

/// Assert that a header exists (regardless of value)
pub fn assert_header_present(response: &reqwest::Response, header: &str, context: &str) {
    assert!(
        response.headers().contains_key(header),
        "{}: expected {} header to be present",
        context,
        header
    );
}

/// Follow permanent redirects from an initial URL until a non-redirect response (up to 10 hops).
pub async fn follow_redirects(initial_url: &str) -> String {
    let c = client();
    let mut current_url = initial_url.to_string();
    for i in 0..10 {
        let resp = c
            .get(&current_url)
            .send()
            .await
            .unwrap_or_else(|e| panic!("Request {} to {} failed: {}", i + 1, current_url, e));
        let status = resp.status().as_u16();
        if status == 301 || status == 308 {
            let location = resp
                .headers()
                .get("location")
                .unwrap_or_else(|| {
                    panic!(
                        "{} redirect {} from {} has no Location header",
                        status,
                        i + 1,
                        current_url
                    )
                })
                .to_str()
                .unwrap_or_else(|e| {
                    panic!(
                        "Invalid Location header on redirect {} from {}: {}",
                        i + 1,
                        current_url,
                        e
                    )
                });
            current_url = location.to_string();
        } else if resp.status().is_redirection() {
            panic!(
                "Request {} to {} returned unexpected redirect ({}). Only 301/308 redirects are expected.",
                i + 1,
                current_url,
                status
            );
        } else {
            return current_url;
        }
    }
    panic!(
        "Too many redirects (>10) starting from {}. Last URL: {}",
        initial_url, current_url
    );
}

/// Helper to POST form data and return the response.
pub async fn post_form(path: &str, fields: &[(&str, &str)]) -> reqwest::Response {
    let c = client();
    let mut form = std::collections::HashMap::new();
    for (key, value) in fields {
        form.insert(*key, *value);
    }
    c.post(url(path))
        .form(&form)
        .send()
        .await
        .expect("Failed to send POST request")
}

/// Helper to POST form data with captcha bypass header.
pub async fn post_form_with_bypass(
    path: &str,
    fields: &[(&str, &str)],
) -> reqwest::Response {
    let c = client();
    let mut form = std::collections::HashMap::new();
    for (key, value) in fields {
        form.insert(*key, *value);
    }
    c.post(url(path))
        .header("X-Captcha-Bypass", captcha_bypass_secret())
        .form(&form)
        .send()
        .await
        .expect("Failed to send POST request")
}


// ===== HTML parsing helpers =====
//
// These parse the real DOM with `scraper` rather than searching the page source.
// Text comes back entity-decoded, so assertions compare what a reader sees:
// PHP's htmlspecialchars emits `&#039;` where Askama emits `&#x27;`, and both are
// an apostrophe. Escaping regressions still fail, because a payload that was NOT
// escaped parses as markup and stops being text.

use scraper::{Html, Selector};

/// Build a selector, panicking on a malformed one (always a bug in the test).
fn sel(selector: &str) -> Selector {
    Selector::parse(selector)
        .unwrap_or_else(|e| panic!("invalid selector {:?}: {:?}", selector, e))
}

/// Collected text of an element, trimmed.
fn text_of(element: scraper::ElementRef<'_>) -> String {
    element.text().collect::<String>().trim().to_string()
}

// ===== Crack results table =====

/// One row of the crack results table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResultRow {
    /// Row CSS class: `suc` (full match), `part` (prefix match), or `fail`.
    pub class: String,
    /// Hash column — echoes back what was submitted.
    pub hash: String,
    /// Type column: the algorithm name, or `Unknown` for failure rows.
    pub hash_type: String,
    /// Result column: the plaintext, `Not found.`, or `Unrecognized hash format.`
    pub result: String,
}

impl ResultRow {
    /// A green row: the hash was fully cracked.
    pub fn full(hash: &str, hash_type: &str, plaintext: &str) -> Self {
        Self {
            class: "suc".to_string(),
            hash: hash.to_string(),
            hash_type: hash_type.to_string(),
            result: plaintext.to_string(),
        }
    }

    /// A yellow row: only the hash prefix matched, so the plaintext is a candidate.
    pub fn partial(hash: &str, hash_type: &str, plaintext: &str) -> Self {
        Self {
            class: "part".to_string(),
            hash: hash.to_string(),
            hash_type: hash_type.to_string(),
            result: plaintext.to_string(),
        }
    }

    /// A red row: valid hash, no match in any table.
    pub fn not_found(hash: &str) -> Self {
        Self {
            class: "fail".to_string(),
            hash: hash.to_string(),
            hash_type: "Unknown".to_string(),
            result: "Not found.".to_string(),
        }
    }

    /// A red row: the input was not a recognizable hash.
    pub fn bad_format(hash: &str) -> Self {
        Self {
            class: "fail".to_string(),
            hash: hash.to_string(),
            hash_type: "Unknown".to_string(),
            result: "Unrecognized hash format.".to_string(),
        }
    }
}

/// Parse the crack results table into rows, in document order.
///
/// Returns `None` when the page has no results table at all — a GET, or a POST
/// rejected before cracking (bad captcha, too many hashes, empty input).
pub fn parse_results(body: &str) -> Option<Vec<ResultRow>> {
    let document = Html::parse_document(body);
    let table = document.select(&sel("table.results")).next()?;

    let cell = sel("td");
    let rows = table
        .select(&sel("tr"))
        .filter_map(|row| {
            let cells: Vec<_> = row.select(&cell).collect();
            if cells.is_empty() {
                return None; // the <th> header row
            }
            assert_eq!(
                cells.len(),
                3,
                "expected 3 cells in a result row, got {}",
                cells.len()
            );
            let class = row
                .value()
                .attr("class")
                .unwrap_or_else(|| panic!("result row has no class attribute"));
            Some(ResultRow {
                class: class.to_string(),
                hash: text_of(cells[0]),
                hash_type: text_of(cells[1]),
                result: text_of(cells[2]),
            })
        })
        .collect();

    Some(rows)
}

/// Parse the crack results table, panicking when the page has no results table.
pub fn results(body: &str) -> Vec<ResultRow> {
    parse_results(body).unwrap_or_else(|| {
        panic!(
            "expected a crack results table in the response, found none.\nBody preview: {}...",
            body.chars().take(500).collect::<String>()
        )
    })
}

// ===== Page metadata =====

/// Site-wide defaults from PHP's URLParse.php ($DEFAULT_TITLE etc). Pages that
/// declare no title/description/keywords of their own render these.
pub const DEFAULT_TITLE: &str =
    "CrackStation - Online Password Hash Cracking - MD5, SHA1, Linux, Rainbow Tables, etc.";
pub const DEFAULT_DESCRIPTION: &str =
    "Crackstation is the most effective hash cracking service. We crack: MD5, SHA1, SHA2, WPA, and much more...";
pub const DEFAULT_KEYWORDS: &str =
    "md5 cracking, sha1 cracking, hash cracking, password cracking";

/// The `<head>` metadata of a rendered page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PageMeta {
    pub title: String,
    pub description: String,
    pub keywords: String,
}

/// Read the `content` attribute of `<meta name="...">`.
fn meta_content(document: &Html, name: &str) -> String {
    let selector = sel(&format!(r#"meta[name="{}"]"#, name));
    document
        .select(&selector)
        .next()
        .unwrap_or_else(|| panic!("page has no <meta name=\"{}\">", name))
        .value()
        .attr("content")
        .unwrap_or_else(|| panic!("<meta name=\"{}\"> has no content attribute", name))
        .to_string()
}

/// Parse `<title>`, `<meta name="description">`, and `<meta name="keywords">`.
pub fn page_meta(body: &str) -> PageMeta {
    let document = Html::parse_document(body);
    let title = document
        .select(&sel("title"))
        .next()
        .unwrap_or_else(|| panic!("page has no <title>"));
    PageMeta {
        title: text_of(title),
        description: meta_content(&document, "description"),
        keywords: meta_content(&document, "keywords"),
    }
}

/// Text of the page's single `<h1>`, panicking if there isn't exactly one.
pub fn h1(body: &str) -> String {
    let document = Html::parse_document(body);
    let headings: Vec<_> = document.select(&sel("h1")).collect();
    assert_eq!(
        headings.len(),
        1,
        "expected exactly one <h1> on the page, found {}",
        headings.len()
    );
    text_of(headings[0])
}

/// Count elements matching a CSS selector.
pub fn count_matching(body: &str, selector: &str) -> usize {
    Html::parse_document(body).select(&sel(selector)).count()
}

/// Text content of the `<textarea name="hashes">`, which the server repopulates
/// with whatever was submitted.
pub fn submitted_hashes_textarea(body: &str) -> String {
    let document = Html::parse_document(body);
    let textarea = document
        .select(&sel(r#"textarea[name="hashes"]"#))
        .next()
        .expect("page has no <textarea name=\"hashes\">");
    textarea.text().collect::<String>()
}

/// GET a path, assert it returns exactly 200, and return the body.
pub async fn get_ok(path: &str) -> String {
    let resp = client()
        .get(url(path))
        .send()
        .await
        .unwrap_or_else(|e| panic!("GET {} failed: {}", path, e));
    assert_eq!(
        resp.status().as_u16(),
        200,
        "GET {} should return exactly 200",
        path
    );
    resp.text().await.expect("response body")
}
