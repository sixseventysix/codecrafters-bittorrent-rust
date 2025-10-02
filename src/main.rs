use serde_json;
use std::env;
use std::fs;
use std::net::TcpStream;
use std::io::{Write, Read};

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

fn download_piece_from_peer(
    stream: &mut TcpStream,
    piece_index: usize,
    piece_length: i64,
    total_length: i64,
    piece_hashes: &[u8],
) -> Vec<u8> {
    // Calculate piece size for this piece
    let total_pieces = (total_length as f64 / piece_length as f64).ceil() as usize;
    let is_last_piece = piece_index == total_pieces - 1;
    let current_piece_length = if is_last_piece {
        total_length - (piece_index as i64 * piece_length)
    } else {
        piece_length
    };

    // Download the piece in blocks of 16 KiB
    const BLOCK_SIZE: i64 = 16 * 1024;
    let mut piece_data = Vec::new();

    let num_blocks = (current_piece_length as f64 / BLOCK_SIZE as f64).ceil() as usize;
    for block_index in 0..num_blocks {
        let block_begin = block_index as i64 * BLOCK_SIZE;
        let block_length = if block_index == num_blocks - 1 {
            current_piece_length - block_begin
        } else {
            BLOCK_SIZE
        };

        // Send request message
        let mut request_msg = Vec::new();
        request_msg.extend_from_slice(&13u32.to_be_bytes()); // length = 13
        request_msg.push(6u8); // id = 6 (request)
        request_msg.extend_from_slice(&(piece_index as u32).to_be_bytes()); // index
        request_msg.extend_from_slice(&(block_begin as u32).to_be_bytes()); // begin
        request_msg.extend_from_slice(&(block_length as u32).to_be_bytes()); // length
        stream.write_all(&request_msg).unwrap();

        // Read piece message
        let mut length_prefix = [0u8; 4];
        stream.read_exact(&mut length_prefix).unwrap();
        let msg_length = u32::from_be_bytes(length_prefix);
        let mut message = vec![0u8; msg_length as usize];
        stream.read_exact(&mut message).unwrap();

        // message[0] should be 7 (piece)
        // message[1..5] is index
        // message[5..9] is begin
        // message[9..] is block data
        piece_data.extend_from_slice(&message[9..]);
    }

    // Verify piece hash
    let mut hasher = Sha1::new();
    hasher.update(&piece_data);
    let calculated_hash = hasher.finalize();
    let expected_hash = &piece_hashes[piece_index * 20..(piece_index + 1) * 20];

    if calculated_hash.as_slice() != expected_hash {
        panic!("Piece hash mismatch for piece {}!", piece_index);
    }

    piece_data
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
    } else if command == "download" {
        // Parse arguments: download -o <output_file> <torrent_file>
        let output_file = &args[3];
        let torrent_file = &args[4];

        // Parse torrent file
        let bytes = fs::read(torrent_file).unwrap();
        let torrent: serde_bencode::value::Value = serde_bencode::from_bytes(&bytes).unwrap();

        let mut tracker_url = String::new();
        let mut length: i64 = 0;
        let mut piece_length: i64 = 0;
        let mut piece_hashes: Vec<u8> = Vec::new();
        let mut info_hash_bytes = Vec::new();

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
                info_hash_bytes = hasher.finalize().to_vec();
            }
        }

        // Calculate total number of pieces
        let total_pieces = (length as f64 / piece_length as f64).ceil() as usize;

        // Get peers from tracker
        let info_hash_encoded: String = info_hash_bytes.iter()
            .map(|b| format!("%{:02x}", b))
            .collect();

        let peer_id = "00112233445566778899";
        let request_url = format!(
            "{}?info_hash={}&peer_id={}&port=6881&uploaded=0&downloaded=0&left={}&compact=1",
            tracker_url, info_hash_encoded, peer_id, length
        );

        let response = reqwest::blocking::get(&request_url).unwrap();
        let response_bytes = response.bytes().unwrap();
        let tracker_response: serde_bencode::value::Value =
            serde_bencode::from_bytes(&response_bytes).unwrap();

        let mut peer_addr = String::new();
        if let serde_bencode::value::Value::Dict(response_dict) = tracker_response {
            if let Some(serde_bencode::value::Value::Bytes(peers)) = response_dict.get(b"peers".as_ref()) {
                // Use first peer
                let peer_chunk = &peers[0..6];
                let ip = format!("{}.{}.{}.{}",
                    peer_chunk[0], peer_chunk[1], peer_chunk[2], peer_chunk[3]);
                let port = u16::from_be_bytes([peer_chunk[4], peer_chunk[5]]);
                peer_addr = format!("{}:{}", ip, port);
            }
        }

        // Connect to peer and perform handshake
        let mut stream = TcpStream::connect(&peer_addr).unwrap();

        let mut handshake = Vec::new();
        handshake.push(19u8);
        handshake.extend_from_slice(b"BitTorrent protocol");
        handshake.extend_from_slice(&[0u8; 8]);
        handshake.extend_from_slice(&info_hash_bytes);
        handshake.extend_from_slice(peer_id.as_bytes());

        stream.write_all(&handshake).unwrap();

        let mut response = [0u8; 68];
        stream.read_exact(&mut response).unwrap();

        // Read bitfield message
        let mut length_prefix = [0u8; 4];
        stream.read_exact(&mut length_prefix).unwrap();
        let msg_length = u32::from_be_bytes(length_prefix);

        let mut message = vec![0u8; msg_length as usize];
        stream.read_exact(&mut message).unwrap();
        // message[0] should be 5 (bitfield)

        // Send interested message
        let interested_msg = [0u8, 0u8, 0u8, 1u8, 2u8]; // length=1, id=2
        stream.write_all(&interested_msg).unwrap();

        // Read unchoke message
        stream.read_exact(&mut length_prefix).unwrap();
        let msg_length = u32::from_be_bytes(length_prefix);
        let mut message = vec![0u8; msg_length as usize];
        stream.read_exact(&mut message).unwrap();
        // message[0] should be 1 (unchoke)

        // Download all pieces
        let mut file_data = Vec::new();
        for piece_index in 0..total_pieces {
            let piece_data = download_piece_from_peer(&mut stream, piece_index, piece_length, length, &piece_hashes);
            file_data.extend_from_slice(&piece_data);
        }

        // Write complete file to disk
        fs::write(output_file, &file_data).unwrap();
        println!("Downloaded {} to {}.", torrent_file, output_file);
    } else if command == "download_piece" {
        // Parse arguments: download_piece -o <output_file> <torrent_file> <piece_index>
        let output_file = &args[3];
        let torrent_file = &args[4];
        let piece_index: usize = args[5].parse().unwrap();

        // Parse torrent file
        let bytes = fs::read(torrent_file).unwrap();
        let torrent: serde_bencode::value::Value = serde_bencode::from_bytes(&bytes).unwrap();

        let mut tracker_url = String::new();
        let mut length: i64 = 0;
        let mut piece_length: i64 = 0;
        let mut piece_hashes: Vec<u8> = Vec::new();
        let mut info_hash_bytes = Vec::new();

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
                info_hash_bytes = hasher.finalize().to_vec();
            }
        }

        // Get peers from tracker
        let info_hash_encoded: String = info_hash_bytes.iter()
            .map(|b| format!("%{:02x}", b))
            .collect();

        let peer_id = "00112233445566778899";
        let request_url = format!(
            "{}?info_hash={}&peer_id={}&port=6881&uploaded=0&downloaded=0&left={}&compact=1",
            tracker_url, info_hash_encoded, peer_id, length
        );

        let response = reqwest::blocking::get(&request_url).unwrap();
        let response_bytes = response.bytes().unwrap();
        let tracker_response: serde_bencode::value::Value =
            serde_bencode::from_bytes(&response_bytes).unwrap();

        let mut peer_addr = String::new();
        if let serde_bencode::value::Value::Dict(response_dict) = tracker_response {
            if let Some(serde_bencode::value::Value::Bytes(peers)) = response_dict.get(b"peers".as_ref()) {
                // Use first peer
                let peer_chunk = &peers[0..6];
                let ip = format!("{}.{}.{}.{}",
                    peer_chunk[0], peer_chunk[1], peer_chunk[2], peer_chunk[3]);
                let port = u16::from_be_bytes([peer_chunk[4], peer_chunk[5]]);
                peer_addr = format!("{}:{}", ip, port);
            }
        }

        // Connect to peer and perform handshake
        let mut stream = TcpStream::connect(&peer_addr).unwrap();

        let mut handshake = Vec::new();
        handshake.push(19u8);
        handshake.extend_from_slice(b"BitTorrent protocol");
        handshake.extend_from_slice(&[0u8; 8]);
        handshake.extend_from_slice(&info_hash_bytes);
        handshake.extend_from_slice(peer_id.as_bytes());

        stream.write_all(&handshake).unwrap();

        let mut response = [0u8; 68];
        stream.read_exact(&mut response).unwrap();

        // Read bitfield message
        let mut length_prefix = [0u8; 4];
        stream.read_exact(&mut length_prefix).unwrap();
        let msg_length = u32::from_be_bytes(length_prefix);

        let mut message = vec![0u8; msg_length as usize];
        stream.read_exact(&mut message).unwrap();
        // message[0] should be 5 (bitfield)

        // Send interested message
        let interested_msg = [0u8, 0u8, 0u8, 1u8, 2u8]; // length=1, id=2
        stream.write_all(&interested_msg).unwrap();

        // Read unchoke message
        stream.read_exact(&mut length_prefix).unwrap();
        let msg_length = u32::from_be_bytes(length_prefix);
        let mut message = vec![0u8; msg_length as usize];
        stream.read_exact(&mut message).unwrap();
        // message[0] should be 1 (unchoke)

        // Download the piece
        let piece_data = download_piece_from_peer(&mut stream, piece_index, piece_length, length, &piece_hashes);

        // Write piece to file
        fs::write(output_file, &piece_data).unwrap();
        println!("Piece {} downloaded to {}.", piece_index, output_file);
    } else if command == "handshake" {
        let torrent_file = &args[2];
        let peer_addr = &args[3];

        // Parse torrent file and calculate info hash
        let bytes = fs::read(torrent_file).unwrap();
        let torrent: serde_bencode::value::Value = serde_bencode::from_bytes(&bytes).unwrap();

        let mut info_hash_bytes = Vec::new();

        if let serde_bencode::value::Value::Dict(dict) = torrent {
            if let Some(info_value) = dict.get(b"info".as_ref()) {
                // Calculate info hash (raw bytes)
                let info_bencoded = serde_bencode::to_bytes(info_value).unwrap();
                let mut hasher = Sha1::new();
                hasher.update(&info_bencoded);
                info_hash_bytes = hasher.finalize().to_vec();
            }
        }

        // Generate peer ID (20 bytes)
        let peer_id = b"00112233445566778899";

        // Construct handshake message
        let mut handshake = Vec::new();
        handshake.push(19u8); // length of protocol string
        handshake.extend_from_slice(b"BitTorrent protocol"); // protocol string
        handshake.extend_from_slice(&[0u8; 8]); // 8 reserved bytes
        handshake.extend_from_slice(&info_hash_bytes); // info hash (20 bytes)
        handshake.extend_from_slice(peer_id); // peer id (20 bytes)

        // Connect to peer
        let mut stream = TcpStream::connect(peer_addr).unwrap();

        // Send handshake
        stream.write_all(&handshake).unwrap();

        // Receive handshake response (68 bytes total)
        let mut response = [0u8; 68];
        stream.read_exact(&mut response).unwrap();

        // Extract peer ID from response (last 20 bytes)
        let received_peer_id = &response[48..68];
        println!("Peer ID: {}", hex::encode(received_peer_id));
    } else {
        println!("unknown command: {}", args[1])
    }
}
