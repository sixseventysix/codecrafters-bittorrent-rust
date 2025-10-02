use serde_bencode;
use sha1::{Sha1, Digest};
use std::fs;
use anyhow::{Result, Context, anyhow};

pub struct TorrentInfo {
    pub tracker_url: String,
    pub length: i64,
    pub piece_length: i64,
    pub piece_hashes: Vec<u8>,
    pub info_hash: Vec<u8>,
}

/// Parse torrent file and extract metadata
pub fn parse_torrent_file(torrent_path: &str) -> Result<TorrentInfo> {
    let bytes = fs::read(torrent_path)
        .context("Failed to read torrent file")?;
    let torrent: serde_bencode::value::Value = serde_bencode::from_bytes(&bytes)
        .context("Failed to decode torrent file")?;

    let serde_bencode::value::Value::Dict(dict) = torrent else {
        return Err(anyhow!("Torrent file is not a valid dictionary"));
    };

    // Extract tracker URL
    let tracker_url = dict.get(b"announce".as_ref())
        .and_then(|v| if let serde_bencode::value::Value::Bytes(b) = v { Some(b) } else { None })
        .and_then(|b| String::from_utf8(b.clone()).ok())
        .ok_or_else(|| anyhow!("Missing or invalid announce URL"))?;

    // Extract info dictionary
    let info_value = dict.get(b"info".as_ref())
        .ok_or_else(|| anyhow!("Missing info dictionary"))?;

    let serde_bencode::value::Value::Dict(info) = info_value else {
        return Err(anyhow!("Info is not a valid dictionary"));
    };

    // Extract length
    let length = info.get(b"length".as_ref())
        .and_then(|v| if let serde_bencode::value::Value::Int(i) = v { Some(*i) } else { None })
        .ok_or_else(|| anyhow!("Missing or invalid length"))?;

    // Extract piece length
    let piece_length = info.get(b"piece length".as_ref())
        .and_then(|v| if let serde_bencode::value::Value::Int(i) = v { Some(*i) } else { None })
        .ok_or_else(|| anyhow!("Missing or invalid piece length"))?;

    // Extract piece hashes
    let piece_hashes = info.get(b"pieces".as_ref())
        .and_then(|v| if let serde_bencode::value::Value::Bytes(b) = v { Some(b.clone()) } else { None })
        .ok_or_else(|| anyhow!("Missing or invalid pieces"))?;

    // Calculate info hash
    let info_bencoded = serde_bencode::to_bytes(info_value)
        .context("Failed to encode info dictionary")?;
    let mut hasher = Sha1::new();
    hasher.update(&info_bencoded);
    let info_hash = hasher.finalize().to_vec();

    Ok(TorrentInfo {
        tracker_url,
        length,
        piece_length,
        piece_hashes,
        info_hash,
    })
}
