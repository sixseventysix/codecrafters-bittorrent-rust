use serde_json;
use std::env;
use std::fs;

use serde_bencode;
use sha1::{Sha1, Digest};

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
    } else {
        println!("unknown command: {}", args[1])
    }
}
