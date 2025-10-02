use serde_bencode;
use reqwest;

use crate::torrent::TorrentInfo;
use crate::magnet::MagnetLink;

pub const PEER_ID: &str = "00112233445566778899";

/// Get list of peers from tracker
pub fn get_peers_from_tracker(torrent_info: &TorrentInfo) -> Vec<String> {
    let info_hash_encoded: String = torrent_info.info_hash.iter()
        .map(|b| format!("%{:02x}", b))
        .collect();

    let request_url = format!(
        "{}?info_hash={}&peer_id={}&port=6881&uploaded=0&downloaded=0&left={}&compact=1",
        torrent_info.tracker_url, info_hash_encoded, PEER_ID, torrent_info.length
    );

    let response = reqwest::blocking::get(&request_url).unwrap();
    let response_bytes = response.bytes().unwrap();
    let tracker_response: serde_bencode::value::Value =
        serde_bencode::from_bytes(&response_bytes).unwrap();

    decode_peer_list(tracker_response)
}

/// Get list of peers from tracker using magnet link info
pub fn get_peers_from_magnet(magnet_info: &MagnetLink) -> Vec<String> {
    let info_hash_bytes = hex::decode(&magnet_info.info_hash).unwrap();
    let info_hash_encoded: String = info_hash_bytes.iter()
        .map(|b| format!("%{:02x}", b))
        .collect();

    let request_url = format!(
        "{}?info_hash={}&peer_id={}&port=6881&uploaded=0&downloaded=0&compact=1&event=started",
        magnet_info.tracker_url, info_hash_encoded, PEER_ID
    );

    let response = reqwest::blocking::get(&request_url).unwrap();
    let response_bytes = response.bytes().unwrap();
    let tracker_response: serde_bencode::value::Value =
        serde_bencode::from_bytes(&response_bytes).unwrap();

    decode_peer_list(tracker_response)
}

fn decode_peer_list(tracker_response: serde_bencode::value::Value) -> Vec<String> {
    let mut peers = Vec::new();
    if let serde_bencode::value::Value::Dict(response_dict) = tracker_response {
        if let Some(serde_bencode::value::Value::Bytes(peers_bytes)) = response_dict.get(b"peers".as_ref()) {
            // Decode compact peer format (6 bytes per peer)
            for peer_chunk in peers_bytes.chunks(6) {
                let ip = format!("{}.{}.{}.{}",
                    peer_chunk[0], peer_chunk[1], peer_chunk[2], peer_chunk[3]);
                let port = u16::from_be_bytes([peer_chunk[4], peer_chunk[5]]);
                peers.push(format!("{}:{}", ip, port));
            }
        }
    }
    peers
}
