use serde_json;
use std::env;
use std::fs;

use serde_bencode;
use sha1::{Sha1, Digest};
use reqwest;

fn decode_bencoded_value(encoded_value: &str) -> serde_json::Value {
    let decoded: serde_bencode::value::Value = serde_bencode::from_str(encoded_value).unwrap();

    match decoded {
        serde_bencode::value::Value::Bytes(b) => {
            serde_json::Value::String(String::from_utf8(b).unwrap())
        }
        serde_bencode::value::Value::Int(i) => {
            serde_json::Value::Number(i.into())
        }
        serde_bencode::value::Value::List(list) => {
            let json_list: Vec<serde_json::Value> = list
                .into_iter()
                .map(|v| bencode_to_json(v))
                .collect();
            serde_json::Value::Array(json_list)
        }
        serde_bencode::value::Value::Dict(dict) => {
            let json_map: serde_json::Map<String, serde_json::Value> = dict
                .into_iter()
                .map(|(k, v)| (String::from_utf8(k).unwrap(), bencode_to_json(v)))
                .collect();
            serde_json::Value::Object(json_map)
        }
    }
}

fn bencode_to_json(value: serde_bencode::value::Value) -> serde_json::Value {
    match value {
        serde_bencode::value::Value::Bytes(b) => {
            serde_json::Value::String(String::from_utf8(b).unwrap())
        }
        serde_bencode::value::Value::Int(i) => {
            serde_json::Value::Number(i.into())
        }
        serde_bencode::value::Value::List(list) => {
            let json_list: Vec<serde_json::Value> = list
                .into_iter()
                .map(|v| bencode_to_json(v))
                .collect();
            serde_json::Value::Array(json_list)
        }
        serde_bencode::value::Value::Dict(dict) => {
            let json_map: serde_json::Map<String, serde_json::Value> = dict
                .into_iter()
                .map(|(k, v)| (String::from_utf8(k).unwrap(), bencode_to_json(v)))
                .collect();
            serde_json::Value::Object(json_map)
        }
    }
}

// Usage: your_program.sh decode "<encoded_value>"
fn main() {
    let args: Vec<String> = env::args().collect();
    let command = &args[1];

    if command == "decode" {
        let encoded_value = &args[2];
        let decoded_value = decode_bencoded_value(encoded_value);
        println!("{}", decoded_value.to_string());
    } else if command == "info" {
        let torrent_file = &args[2];
        let bytes = fs::read(torrent_file).unwrap();
        let torrent: serde_bencode::value::Value = serde_bencode::from_bytes(&bytes).unwrap();

        if let serde_bencode::value::Value::Dict(dict) = torrent {
            // Extract tracker URL
            if let Some(serde_bencode::value::Value::Bytes(announce)) = dict.get(b"announce".as_ref()) {
                let tracker_url = String::from_utf8(announce.clone()).unwrap();
                println!("Tracker URL: {}", tracker_url);
            }

            // Extract length and calculate info hash from info dictionary
            if let Some(info_value) = dict.get(b"info".as_ref()) {
                // Extract length, piece length, and pieces
                if let serde_bencode::value::Value::Dict(info) = info_value {
                    if let Some(serde_bencode::value::Value::Int(length)) = info.get(b"length".as_ref()) {
                        println!("Length: {}", length);
                    }
                }

                // Calculate info hash
                let info_bencoded = serde_bencode::to_bytes(info_value).unwrap();
                let mut hasher = Sha1::new();
                hasher.update(&info_bencoded);
                let info_hash = hasher.finalize();
                println!("Info Hash: {}", hex::encode(info_hash));

                // Extract piece length and piece hashes
                if let serde_bencode::value::Value::Dict(info) = info_value {
                    if let Some(serde_bencode::value::Value::Int(piece_length)) = info.get(b"piece length".as_ref()) {
                        println!("Piece Length: {}", piece_length);
                    }

                    if let Some(serde_bencode::value::Value::Bytes(pieces)) = info.get(b"pieces".as_ref()) {
                        println!("Piece Hashes:");
                        // Each SHA-1 hash is 20 bytes
                        for chunk in pieces.chunks(20) {
                            println!("{}", hex::encode(chunk));
                        }
                    }
                }
            }
        }
    } else if command == "peers" {
        let torrent_file = &args[2];
        let bytes = fs::read(torrent_file).unwrap();
        let torrent: serde_bencode::value::Value = serde_bencode::from_bytes(&bytes).unwrap();

        if let serde_bencode::value::Value::Dict(dict) = torrent {
            let mut tracker_url = String::new();
            let mut length: i64 = 0;
            let mut info_hash_bytes = Vec::new();

            // Extract tracker URL
            if let Some(serde_bencode::value::Value::Bytes(announce)) = dict.get(b"announce".as_ref()) {
                tracker_url = String::from_utf8(announce.clone()).unwrap();
            }

            // Extract length and calculate info hash
            if let Some(info_value) = dict.get(b"info".as_ref()) {
                if let serde_bencode::value::Value::Dict(info) = info_value {
                    if let Some(serde_bencode::value::Value::Int(l)) = info.get(b"length".as_ref()) {
                        length = *l;
                    }
                }

                // Calculate info hash (raw bytes, not hex)
                let info_bencoded = serde_bencode::to_bytes(info_value).unwrap();
                let mut hasher = Sha1::new();
                hasher.update(&info_bencoded);
                info_hash_bytes = hasher.finalize().to_vec();
            }

            // URL encode the info_hash
            let info_hash_encoded: String = info_hash_bytes.iter()
                .map(|b| format!("%{:02x}", b))
                .collect();

            // Build tracker request URL
            let peer_id = "00112233445566778899"; // 20 character peer ID
            let port = 6881;
            let uploaded = 0;
            let downloaded = 0;
            let left = length;
            let compact = 1;

            let request_url = format!(
                "{}?info_hash={}&peer_id={}&port={}&uploaded={}&downloaded={}&left={}&compact={}",
                tracker_url, info_hash_encoded, peer_id, port, uploaded, downloaded, left, compact
            );

            // Make GET request to tracker
            let response = reqwest::blocking::get(&request_url).unwrap();
            let response_bytes = response.bytes().unwrap();

            // Parse tracker response
            let tracker_response: serde_bencode::value::Value =
                serde_bencode::from_bytes(&response_bytes).unwrap();

            if let serde_bencode::value::Value::Dict(response_dict) = tracker_response {
                if let Some(serde_bencode::value::Value::Bytes(peers)) = response_dict.get(b"peers".as_ref()) {
                    // Decode compact peer format (6 bytes per peer: 4 for IP, 2 for port)
                    for peer_chunk in peers.chunks(6) {
                        let ip = format!("{}.{}.{}.{}",
                            peer_chunk[0], peer_chunk[1], peer_chunk[2], peer_chunk[3]);
                        let port = u16::from_be_bytes([peer_chunk[4], peer_chunk[5]]);
                        println!("{}:{}", ip, port);
                    }
                }
            }
        }
    } else {
        println!("unknown command: {}", args[1])
    }
}
