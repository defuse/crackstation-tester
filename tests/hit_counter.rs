//! Hit counter tests
//!
//! Tests for page hit counting functionality including bot detection.

mod common;

use common::url;
use reqwest::header::USER_AGENT;
use reqwest::Client;
use scraper::{Html, Selector};

/// Extract hit counts from page HTML.
/// Returns (page_hits, unique_hits).
fn extract_hit_counts(html: &str) -> (i64, i64) {
    let document = Html::parse_document(html);

    let th_selector = Selector::parse("th").unwrap();
    let td_selector = Selector::parse("td").unwrap();

    let mut page_hits: Option<i64> = None;
    let mut unique_hits: Option<i64> = None;

    let tr_selector = Selector::parse("tr").unwrap();
    for tr in document.select(&tr_selector) {
        let ths: Vec<_> = tr.select(&th_selector).collect();
        let tds: Vec<_> = tr.select(&td_selector).collect();

        if let (Some(th), Some(td)) = (ths.first(), tds.first()) {
            let header_text = th.text().collect::<String>();
            let value_text = td.text().collect::<String>();

            if header_text.contains("Page Hits") {
                page_hits = Some(
                    value_text
                        .trim()
                        .parse()
                        .unwrap_or_else(|e| {
                            panic!(
                                "Page Hits value '{}' is not a number: {}",
                                value_text.trim(),
                                e
                            )
                        }),
                );
            } else if header_text.contains("Unique Hits") {
                unique_hits = Some(
                    value_text
                        .trim()
                        .parse()
                        .unwrap_or_else(|e| {
                            panic!(
                                "Unique Hits value '{}' is not a number: {}",
                                value_text.trim(),
                                e
                            )
                        }),
                );
            }
        }
    }

    (
        page_hits.expect("Failed to find Page Hits in footer"),
        unique_hits.expect("Failed to find Unique Hits in footer"),
    )
}

/// Second hit from the same IP should only increment non-unique counter.
#[tokio::test]
async fn hit_increments_non_unique_only() {
    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .expect("Failed to create HTTP client");

    // Use the about page to avoid conflicts with other tests
    let page_url = url("/about-us.htm");

    // First hit
    let resp1 = client.get(&page_url).send().await.expect("First request failed");
    assert_eq!(resp1.status().as_u16(), 200, "first request should return 200");
    let body1 = resp1.text().await.expect("Failed to read first response");
    let (page_hits_1, unique_hits_1) = extract_hit_counts(&body1);

    // Second hit (same IP, should only increment non-unique)
    let resp2 = client.get(&page_url).send().await.expect("Second request failed");
    assert_eq!(resp2.status().as_u16(), 200, "second request should return 200");
    let body2 = resp2.text().await.expect("Failed to read second response");
    let (page_hits_2, unique_hits_2) = extract_hit_counts(&body2);

    assert_eq!(
        page_hits_2,
        page_hits_1 + 1,
        "Page Hits should increase by 1 on second hit (was {}, now {})",
        page_hits_1,
        page_hits_2
    );

    assert_eq!(
        unique_hits_2,
        unique_hits_1,
        "Unique Hits should not change for same IP (was {}, now {})",
        unique_hits_1,
        unique_hits_2
    );
}

/// Bot requests should NOT increment the hit counter.
#[tokio::test]
async fn hit_counter_bot_not_counted() {
    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .expect("Failed to create HTTP client");

    // Use the downloads page to avoid race conditions
    let page_url = url("/downloads.htm");

    // Get current count with normal UA
    let resp1 = client
        .get(&page_url)
        .header(USER_AGENT, "Mozilla/5.0 TestBrowser/1.0")
        .send()
        .await
        .expect("First request failed");
    assert_eq!(resp1.status().as_u16(), 200);
    let body1 = resp1.text().await.expect("Failed to read response");
    let (page_hits_before, _) = extract_hit_counts(&body1);

    // Request with "bot" in UA - should NOT be counted
    let resp_bot = client
        .get(&page_url)
        .header(USER_AGENT, "TestBot/1.0")
        .send()
        .await
        .expect("Bot request failed");
    assert_eq!(resp_bot.status().as_u16(), 200);

    // Check count again with normal UA
    let resp2 = client
        .get(&page_url)
        .header(USER_AGENT, "Mozilla/5.0 TestBrowser/1.0")
        .send()
        .await
        .expect("Second request failed");
    assert_eq!(resp2.status().as_u16(), 200);
    let body2 = resp2.text().await.expect("Failed to read response");
    let (page_hits_after, _) = extract_hit_counts(&body2);

    // Should increment by exactly 1 (bot request ignored)
    assert_eq!(
        page_hits_after,
        page_hits_before + 1,
        "Bot UA should be ignored. Before: {}, After: {} (expected +1, got +{})",
        page_hits_before,
        page_hits_after,
        page_hits_after - page_hits_before
    );
}
