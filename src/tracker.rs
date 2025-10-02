use serde_bencode;
use reqwest;
use anyhow::{Result, Context, anyhow};

use crate::torrent::TorrentInfo;
use crate::magnet::MagnetLink;

pub const PEER_ID: &str = "00112233445566778899";

/// Get list of peers from tracker
pub fn get_peers_from_tracker(torrent_info: &TorrentInfo) -> Result<Vec<String>> {
    let info_hash_encoded: String = torrent_info.info_hash.iter()
        .map(|b| format!("%{:02x}", b))
        .collect();

    let request_url = format!(
        "{}?info_hash={}&peer_id={}&port=6881&uploaded=0&downloaded=0&left={}&compact=1",
        torrent_info.tracker_url, info_hash_encoded, PEER_ID, torrent_info.length
    );

    let response = reqwest::blocking::get(&request_url)
        .context("Failed to send tracker request")?;
    let response_bytes = response.bytes()
        .context("Failed to read tracker response")?;
    let tracker_response: serde_bencode::value::Value =
        serde_bencode::from_bytes(&response_bytes)
            .context("Failed to decode tracker response")?;

    decode_peer_list(tracker_response)
}

/// Get list of peers from tracker using magnet link info
pub fn get_peers_from_magnet(magnet_info: &MagnetLink) -> Result<Vec<String>> {
    let info_hash_bytes = hex::decode(&magnet_info.info_hash)
        .context("Failed to decode info hash")?;
    let info_hash_encoded: String = info_hash_bytes.iter()
        .map(|b| format!("%{:02x}", b))
        .collect();

    let request_url = format!(
        "{}?info_hash={}&peer_id={}&port=6881&uploaded=0&downloaded=0&left=1&compact=1",
        magnet_info.tracker_url, info_hash_encoded, PEER_ID
    );

    let response = reqwest::blocking::get(&request_url)
        .context("Failed to send tracker request")?;
    let response_bytes = response.bytes()
        .context("Failed to read tracker response")?;
    let tracker_response: serde_bencode::value::Value =
        serde_bencode::from_bytes(&response_bytes)
            .context("Failed to decode tracker response")?;

    decode_peer_list(tracker_response)
}

fn decode_peer_list(tracker_response: serde_bencode::value::Value) -> Result<Vec<String>> {
    let mut peers = Vec::new();
    if let serde_bencode::value::Value::Dict(response_dict) = tracker_response {
        // Check if there's a failure reason
        if let Some(serde_bencode::value::Value::Bytes(reason)) = response_dict.get(b"failure reason".as_ref()) {
            let reason_str = String::from_utf8_lossy(reason);
            return Err(anyhow!("Tracker error: {}", reason_str));
        }

        if let Some(serde_bencode::value::Value::Bytes(peers_bytes)) = response_dict.get(b"peers".as_ref()) {
            // Decode compact peer format (6 bytes per peer)
            for peer_chunk in peers_bytes.chunks(6) {
                let ip = format!("{}.{}.{}.{}",
                    peer_chunk[0], peer_chunk[1], peer_chunk[2], peer_chunk[3]);
                let port = u16::from_be_bytes([peer_chunk[4], peer_chunk[5]]);
                peers.push(format!("{}:{}", ip, port));
            }
        } else {
            return Err(anyhow!("No peers found in tracker response"));
        }
    } else {
        return Err(anyhow!("Invalid tracker response format"));
    }

    if peers.is_empty() {
        return Err(anyhow!("Tracker returned empty peer list"));
    }

    Ok(peers)
}
