//! HTTP method handling.
//!
//! RFC 9110 section 15.5.6 makes `Allow` mandatory on a 405, and the value is a property
//! of the *resource*, not of the router: only `/` accepts POST. These tests go through
//! the real router, which the unit tests deliberately do not — they call
//! `handle_unsupported_method` directly, so removing the `MethodRouter` fallback wiring
//! in `main.rs` would leave every unit test passing while the server silently reverted to
//! axum's router-wide `Allow: GET,HEAD,POST`.

mod common;

use common::{client, url};
use reqwest::Method;

/// Registered pages, and the exact `Allow` value each owes a 405.
const EXPECTED_ALLOW: &[(&str, &str)] = &[
    ("/", "GET, HEAD, POST"),
    ("/about-us.htm", "GET, HEAD"),
    ("/legal-privacy.htm", "GET, HEAD"),
];

/// Paths that resolve to no registered page. These answer 404 for every method rather
/// than a 405, because a 405 would advertise methods that do not work: GET on these
/// paths is itself a 404. `/css/main.css` is here because `resolve_path` only knows the
/// page registry, so an existing static asset is indistinguishable from an absent one
/// without a filesystem probe on the request path.
const UNRESOLVED_PATHS: &[&str] = &["/css/main.css", "/no-such-page.htm"];

/// Methods the site serves no resource for. CONNECT is excluded: it is not a request a
/// normal HTTP client can send to an origin server.
const UNSUPPORTED_METHODS: &[Method] =
    &[Method::PUT, Method::DELETE, Method::PATCH, Method::OPTIONS, Method::TRACE];

/// Every unsupported method, on every kind of path, must answer 405 with the `Allow`
/// value belonging to that specific resource.
#[tokio::test]
async fn unsupported_methods_return_405_with_a_per_resource_allow_header() {
    for (path, expected_allow) in EXPECTED_ALLOW {
        for method in UNSUPPORTED_METHODS {
            let response = client()
                .request(method.clone(), url(path))
                .send()
                .await
                .unwrap_or_else(|e| panic!("{method} {path} failed to send: {e}"));

            assert_eq!(
                response.status().as_u16(),
                405,
                "{method} {path} should be 405 Method Not Allowed"
            );
            assert_eq!(
                response
                    .headers()
                    .get(reqwest::header::ALLOW)
                    .unwrap_or_else(|| panic!("{method} {path} 405 carried no Allow header"))
                    .to_str()
                    .expect("Allow header must be ASCII"),
                *expected_allow,
                "{method} {path} advertised the wrong methods"
            );
        }
    }
}

/// A path resolving to no registered page answers 404 for every method, and carries no
/// `Allow` header. Answering 405 there would name GET and HEAD as permitted on a URL
/// where GET returns 404. POST and the unrouted methods reach this through two different
/// code paths, so both are checked.
#[tokio::test]
async fn unresolved_paths_return_404_for_every_method() {
    let mut methods = vec![Method::GET, Method::POST];
    methods.extend(UNSUPPORTED_METHODS.iter().cloned());

    for path in UNRESOLVED_PATHS.iter().filter(|p| **p != "/css/main.css") {
        for method in &methods {
            let response = client()
                .request(method.clone(), url(path))
                .send()
                .await
                .unwrap_or_else(|e| panic!("{method} {path} failed to send: {e}"));

            assert_eq!(
                response.status().as_u16(),
                404,
                "{method} {path} should be 404"
            );
            assert_eq!(
                response.headers().get(reqwest::header::ALLOW),
                None,
                "{method} {path} 404 must not advertise an Allow header"
            );
        }
    }
}

/// A static asset is served for GET, and answers 404 for every other method -- not the
/// 405 its existence would justify, because the dispatcher cannot see the filesystem.
/// Pinned so the inconsistency is recorded rather than drifting silently.
#[tokio::test]
async fn a_static_asset_is_served_for_get_and_404s_for_other_methods() {
    let response = client().get(url("/css/main.css")).send().await.expect("GET failed");
    assert_eq!(response.status().as_u16(), 200, "GET /css/main.css");

    let mut methods = vec![Method::POST];
    methods.extend(UNSUPPORTED_METHODS.iter().cloned());
    for method in &methods {
        let response = client()
            .request(method.clone(), url("/css/main.css"))
            .send()
            .await
            .unwrap_or_else(|e| panic!("{method} /css/main.css failed to send: {e}"));
        assert_eq!(
            response.status().as_u16(),
            404,
            "{method} /css/main.css should be 404"
        );
    }
}

/// POST is routed rather than falling through, so it takes a different code path to the
/// same answer: the dispatcher rejects it before reading the body or recording a hit.
/// `/` is excluded here because it genuinely accepts POST.
#[tokio::test]
async fn post_to_a_page_that_does_not_accept_it_returns_405_with_allow() {
    for (path, expected_allow) in EXPECTED_ALLOW.iter().filter(|(path, _)| *path != "/") {
        let response = client()
            .post(url(path))
            .send()
            .await
            .unwrap_or_else(|e| panic!("POST {path} failed to send: {e}"));

        assert_eq!(
            response.status().as_u16(),
            405,
            "POST {path} should be 405 Method Not Allowed"
        );
        assert_eq!(
            response
                .headers()
                .get(reqwest::header::ALLOW)
                .unwrap_or_else(|| panic!("POST {path} 405 carried no Allow header"))
                .to_str()
                .expect("Allow header must be ASCII"),
            *expected_allow,
            "POST {path} advertised the wrong methods"
        );
    }
}

/// The dispatcher's method match ends in `unreachable!()`, on the argument that the
/// router sends it nothing but GET, HEAD and POST. If that argument is ever wrong the
/// panic is caught by CatchPanicLayer and surfaces as a 500, so assert no method on any
/// path produces one. GET and HEAD are included to pin that adding the `MethodRouter`
/// fallback did not divert them away from the GET route.
#[tokio::test]
async fn no_method_on_any_path_produces_a_server_error() {
    let mut methods = vec![Method::GET, Method::HEAD, Method::POST];
    methods.extend(UNSUPPORTED_METHODS.iter().cloned());

    let paths: Vec<&str> = EXPECTED_ALLOW
        .iter()
        .map(|(path, _)| *path)
        .chain(UNRESOLVED_PATHS.iter().copied())
        .collect();

    for path in &paths {
        for method in &methods {
            let response = client()
                .request(method.clone(), url(path))
                .send()
                .await
                .unwrap_or_else(|e| panic!("{method} {path} failed to send: {e}"));

            assert!(
                !response.status().is_server_error(),
                "{method} {path} returned {} -- the dispatcher's unreachable!() arm may \
                 have been reached",
                response.status()
            );
        }
    }
}

/// HEAD must still be served by the GET route rather than being swept into the new
/// method fallback. Verified against axum 0.7.9's dispatch order, and pinned here.
#[tokio::test]
async fn head_is_still_served_by_the_get_route() {
    for path in ["/", "/about-us.htm", "/css/main.css"] {
        let response = client()
            .head(url(path))
            .send()
            .await
            .unwrap_or_else(|e| panic!("HEAD {path} failed to send: {e}"));

        assert_eq!(
            response.status().as_u16(),
            200,
            "HEAD {path} should be served like GET, not answered with 405"
        );
    }
}
