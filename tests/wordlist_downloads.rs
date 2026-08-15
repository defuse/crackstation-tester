//! The wordlist archives are the product the wordlist page exists to deliver.
//!
//! Both are linked as "HTTP Mirror (Slow)" — the only route for a visitor without a
//! torrent client. Nothing used to verify they were reachable: `/files/*` is a Caddy
//! `handle_path` in production, so a deployment that dropped the rule, or a storage
//! volume that came up without the blobs, answered 404 from those links while every
//! other page on the site looked completely healthy.

mod common;

use common::{client, url};

/// The two archives the wordlist page links, and must keep linking.
const MIRROR_FILES: &[&str] = &["crackstation.txt.gz", "crackstation-human-only.txt.gz"];

/// Each archive must actually be served, not 404 or redirect away.
#[tokio::test]
async fn wordlist_archives_are_served() {
    for file_name in MIRROR_FILES {
        let path = format!("/files/{file_name}");
        let response = client()
            .head(url(&path))
            .send()
            .await
            .unwrap_or_else(|e| panic!("HEAD {path} failed to send: {e}"));

        assert_eq!(
            response.status().as_u16(),
            200,
            "{path} must be served -- it is the wordlist page's HTTP mirror link"
        );
    }
}

/// The page must link exactly the archives that are served, so this fails if a link
/// is renamed on one side only.
#[tokio::test]
async fn the_wordlist_page_links_exactly_those_archives() {
    let body = client()
        .get(url("/crackstation-wordlist-password-cracking-dictionary.htm"))
        .send()
        .await
        .expect("wordlist page request failed")
        .text()
        .await
        .expect("wordlist page body");

    let linked: Vec<String> = body
        .match_indices("href=\"/files/")
        .map(|(index, matched)| {
            let rest = &body[index + matched.len()..];
            rest[..rest.find('"').expect("href must be closed")].to_string()
        })
        .collect();

    assert_eq!(
        linked, MIRROR_FILES,
        "the /files links on the wordlist page changed"
    );
}
