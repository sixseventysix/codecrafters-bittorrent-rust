use serde_bencode;
use sha1::{Sha1, Digest};
use std::fs;

pub struct TorrentInfo {
    pub tracker_url: String,
    pub length: i64,
    pub piece_length: i64,
    pub piece_hashes: Vec<u8>,
    pub info_hash: Vec<u8>,
}

/// Parse torrent file and extract metadata
pub fn parse_torrent_file(torrent_path: &str) -> TorrentInfo {
    let bytes = fs::read(torrent_path).unwrap();
    let torrent: serde_bencode::value::Value = serde_bencode::from_bytes(&bytes).unwrap();

    let mut tracker_url = String::new();
    let mut length: i64 = 0;
    let mut piece_length: i64 = 0;
    let mut piece_hashes: Vec<u8> = Vec::new();
    let mut info_hash: Vec<u8> = Vec::new();

    if let serde_bencode::value::Value::Dict(dict) = torrent {
        // Extract tracker URL
        if let Some(serde_bencode::value::Value::Bytes(announce)) = dict.get(b"announce".as_ref()) {
            tracker_url = String::from_utf8(announce.clone()).unwrap();
        }

        // Extract info and calculate info hash
        if let Some(info_value) = dict.get(b"info".as_ref()) {
            if let serde_bencode::value::Value::Dict(info) = info_value {
                if let Some(serde_bencode::value::Value::Int(l)) = info.get(b"length".as_ref()) {
                    length = *l;
                }
                if let Some(serde_bencode::value::Value::Int(pl)) = info.get(b"piece length".as_ref()) {
                    piece_length = *pl;
                }
                if let Some(serde_bencode::value::Value::Bytes(pieces)) = info.get(b"pieces".as_ref()) {
                    piece_hashes = pieces.clone();
                }
            }

            // Calculate info hash
            let info_bencoded = serde_bencode::to_bytes(info_value).unwrap();
            let mut hasher = Sha1::new();
            hasher.update(&info_bencoded);
            info_hash = hasher.finalize().to_vec();
        }
    }

    TorrentInfo {
        tracker_url,
        length,
        piece_length,
        piece_hashes,
        info_hash,
    }
}
