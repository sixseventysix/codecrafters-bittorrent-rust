use serde_urlencoded;

pub struct MagnetLink {
    pub tracker_url: String,
    pub info_hash: String,
}

/// Parse magnet link and extract info hash and tracker URL
pub fn parse_magnet_link(magnet_link: &str) -> MagnetLink {
    // Remove "magnet:?" prefix
    let query_string = magnet_link.strip_prefix("magnet:?").unwrap();

    // Parse query parameters
    let mut info_hash = String::new();
    let mut tracker_url = String::new();

    for param in query_string.split('&') {
        if let Some((key, value)) = param.split_once('=') {
            match key {
                "xt" => {
                    // Extract info hash from "urn:btih:<hash>"
                    if let Some(hash) = value.strip_prefix("urn:btih:") {
                        info_hash = hash.to_string();
                    }
                }
                "tr" => {
                    // URL decode the tracker URL
                    tracker_url = serde_urlencoded::from_str::<String>(&format!("url={}", value))
                        .ok()
                        .and_then(|s| s.strip_prefix("url=").map(|s| s.to_string()))
                        .unwrap_or_else(|| value.replace("%3A", ":").replace("%2F", "/"));
                }
                _ => {} // Ignore other parameters like "dn"
            }
        }
    }

    MagnetLink {
        tracker_url,
        info_hash,
    }
}
