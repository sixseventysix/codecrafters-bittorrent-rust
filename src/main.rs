use serde_json;
use std::env;
use std::fs;
use std::net::TcpStream;
use std::io::{Write, Read};

use serde_bencode;
use sha1::{Sha1, Digest};
use reqwest;
use serde_urlencoded;

// Structs
struct TorrentInfo {
    tracker_url: String,
    length: i64,
    piece_length: i64,
    piece_hashes: Vec<u8>,
    info_hash: Vec<u8>,
}

struct MagnetLink {
    tracker_url: String,
    info_hash: String,
}

const PEER_ID: &str = "00112233445566778899";
const BLOCK_SIZE: i64 = 16 * 1024;

// Convert hex string to bytes
fn hex_to_bytes(hex: &str) -> Vec<u8> {
    hex::decode(hex).unwrap()
}

// Parse magnet link and extract info hash and tracker URL
fn parse_magnet_link(magnet_link: &str) -> MagnetLink {
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

// Parse torrent file and extract metadata
fn parse_torrent_file(torrent_path: &str) -> TorrentInfo {
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

// Get list of peers from tracker
fn get_peers_from_tracker(torrent_info: &TorrentInfo) -> Vec<String> {
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

// Get list of peers from tracker using magnet link info
fn get_peers_from_magnet(magnet_info: &MagnetLink) -> Vec<String> {
    let info_hash_bytes = hex_to_bytes(&magnet_info.info_hash);
    let info_hash_encoded: String = info_hash_bytes.iter()
        .map(|b| format!("%{:02x}", b))
        .collect();

    // For magnet links, we don't know the file length yet, so we use a small placeholder
    let request_url = format!(
        "{}?info_hash={}&peer_id={}&port=6881&uploaded=0&downloaded=0&left=1&compact=1",
        magnet_info.tracker_url, info_hash_encoded, PEER_ID
    );

    let response = reqwest::blocking::get(&request_url).unwrap();
    let response_bytes = response.bytes().unwrap();
    let tracker_response: serde_bencode::value::Value =
        serde_bencode::from_bytes(&response_bytes).unwrap();

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

// Perform handshake with peer
fn perform_handshake(stream: &mut TcpStream, info_hash: &[u8]) -> [u8; 20] {
    let (peer_id, _) = perform_handshake_with_extensions(stream, info_hash, false);
    peer_id
}

// Perform handshake with peer, optionally with extension support
// Returns (peer_id, peer_supports_extensions)
fn perform_handshake_with_extensions(stream: &mut TcpStream, info_hash: &[u8], support_extensions: bool) -> ([u8; 20], bool) {
    let mut handshake = Vec::new();
    handshake.push(19u8);
    handshake.extend_from_slice(b"BitTorrent protocol");

    // Reserved bytes: set 20th bit from right to 1 if extensions are supported
    let reserved = if support_extensions {
        [0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00]
    } else {
        [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
    };
    handshake.extend_from_slice(&reserved);

    handshake.extend_from_slice(info_hash);
    handshake.extend_from_slice(PEER_ID.as_bytes());

    stream.write_all(&handshake).unwrap();

    let mut response = [0u8; 68];
    stream.read_exact(&mut response).unwrap();

    // Check if peer supports extensions (bit 20 from right in reserved bytes)
    let peer_reserved = &response[20..28];
    let peer_supports_extensions = (peer_reserved[5] & 0x10) != 0;

    // Extract peer ID from response (last 20 bytes)
    let mut peer_id = [0u8; 20];
    peer_id.copy_from_slice(&response[48..68]);

    (peer_id, peer_supports_extensions)
}

// Send extension handshake message
fn send_extension_handshake(stream: &mut TcpStream) {
    // Create bencoded dictionary: {"m": {"ut_metadata": 16}}
    // We'll use extension ID 16 for ut_metadata
    let extension_dict = serde_bencode::value::Value::Dict(
        vec![
            (
                b"m".to_vec(),
                serde_bencode::value::Value::Dict(
                    vec![
                        (b"ut_metadata".to_vec(), serde_bencode::value::Value::Int(16))
                    ].into_iter().collect()
                )
            )
        ].into_iter().collect()
    );

    let bencoded_dict = serde_bencode::to_bytes(&extension_dict).unwrap();

    // Build extension handshake message
    let mut extension_handshake = Vec::new();

    // Message length = 1 (message id = 20) + 1 (extension message id = 0) + bencoded dict length
    let message_length = 1 + 1 + bencoded_dict.len();
    extension_handshake.extend_from_slice(&(message_length as u32).to_be_bytes());

    // Message ID for extension protocol is 20
    extension_handshake.push(20u8);

    // Extension message ID for handshake is 0
    extension_handshake.push(0u8);

    // Bencoded dictionary
    extension_handshake.extend_from_slice(&bencoded_dict);

    stream.write_all(&extension_handshake).unwrap();
}

// Exchange initial peer messages (bitfield, interested, unchoke)
fn exchange_initial_messages(stream: &mut TcpStream) {
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
}

// Receive and parse extension handshake message
// Returns the peer's extension ID for ut_metadata
fn receive_extension_handshake(stream: &mut TcpStream) -> Option<i64> {
    // Read message length
    let mut length_prefix = [0u8; 4];
    stream.read_exact(&mut length_prefix).unwrap();
    let msg_length = u32::from_be_bytes(length_prefix);

    // Read message
    let mut message = vec![0u8; msg_length as usize];
    stream.read_exact(&mut message).unwrap();

    // Check message ID (should be 20 for extension protocol)
    if message[0] != 20 {
        return None;
    }

    // Check extension message ID (should be 0 for handshake)
    if message[1] != 0 {
        return None;
    }

    // Parse bencoded dictionary from payload (starting at index 2)
    let dict_bytes = &message[2..];
    let extension_dict: serde_bencode::value::Value =
        serde_bencode::from_bytes(dict_bytes).unwrap();

    // Extract ut_metadata extension ID from {"m": {"ut_metadata": <ID>}}
    if let serde_bencode::value::Value::Dict(dict) = extension_dict {
        if let Some(serde_bencode::value::Value::Dict(m_dict)) = dict.get(b"m".as_ref()) {
            if let Some(serde_bencode::value::Value::Int(id)) = m_dict.get(b"ut_metadata".as_ref()) {
                return Some(*id);
            }
        }
    }

    None
}

// Exchange messages with extension support
// Returns the peer's ut_metadata extension ID if available
fn exchange_messages_with_extensions(stream: &mut TcpStream, peer_supports_extensions: bool) -> Option<i64> {
    // Read bitfield message
    let mut length_prefix = [0u8; 4];
    stream.read_exact(&mut length_prefix).unwrap();
    let msg_length = u32::from_be_bytes(length_prefix);
    let mut message = vec![0u8; msg_length as usize];
    stream.read_exact(&mut message).unwrap();
    // message[0] should be 5 (bitfield)

    let mut peer_metadata_extension_id = None;

    // Send extension handshake if peer supports extensions
    if peer_supports_extensions {
        send_extension_handshake(stream);

        // Receive extension handshake response
        peer_metadata_extension_id = receive_extension_handshake(stream);
    }

    // Send interested message
    let interested_msg = [0u8, 0u8, 0u8, 1u8, 2u8]; // length=1, id=2
    stream.write_all(&interested_msg).unwrap();

    // Read unchoke message
    stream.read_exact(&mut length_prefix).unwrap();
    let msg_length = u32::from_be_bytes(length_prefix);
    let mut message = vec![0u8; msg_length as usize];
    stream.read_exact(&mut message).unwrap();
    // message[0] should be 1 (unchoke)

    peer_metadata_extension_id
}

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

// Download a single piece from peer
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

    // Download the piece in blocks
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
        let torrent_info = parse_torrent_file(torrent_file);

        println!("Tracker URL: {}", torrent_info.tracker_url);
        println!("Length: {}", torrent_info.length);
        println!("Info Hash: {}", hex::encode(&torrent_info.info_hash));
        println!("Piece Length: {}", torrent_info.piece_length);
        println!("Piece Hashes:");
        for chunk in torrent_info.piece_hashes.chunks(20) {
            println!("{}", hex::encode(chunk));
        }
    } else if command == "peers" {
        let torrent_file = &args[2];
        let torrent_info = parse_torrent_file(torrent_file);
        let peers = get_peers_from_tracker(&torrent_info);

        for peer in peers {
            println!("{}", peer);
        }
    } else if command == "download" {
        let output_file = &args[3];
        let torrent_file = &args[4];

        let torrent_info = parse_torrent_file(torrent_file);
        let peers = get_peers_from_tracker(&torrent_info);
        let peer_addr = &peers[0]; // Use first peer

        let mut stream = TcpStream::connect(peer_addr).unwrap();
        perform_handshake(&mut stream, &torrent_info.info_hash);
        exchange_initial_messages(&mut stream);

        // Download all pieces
        let total_pieces = (torrent_info.length as f64 / torrent_info.piece_length as f64).ceil() as usize;
        let mut file_data = Vec::new();
        for piece_index in 0..total_pieces {
            let piece_data = download_piece_from_peer(
                &mut stream,
                piece_index,
                torrent_info.piece_length,
                torrent_info.length,
                &torrent_info.piece_hashes
            );
            file_data.extend_from_slice(&piece_data);
        }

        fs::write(output_file, &file_data).unwrap();
        println!("Downloaded {} to {}.", torrent_file, output_file);
    } else if command == "download_piece" {
        let output_file = &args[3];
        let torrent_file = &args[4];
        let piece_index: usize = args[5].parse().unwrap();

        let torrent_info = parse_torrent_file(torrent_file);
        let peers = get_peers_from_tracker(&torrent_info);
        let peer_addr = &peers[0]; // Use first peer

        let mut stream = TcpStream::connect(peer_addr).unwrap();
        perform_handshake(&mut stream, &torrent_info.info_hash);
        exchange_initial_messages(&mut stream);

        let piece_data = download_piece_from_peer(
            &mut stream,
            piece_index,
            torrent_info.piece_length,
            torrent_info.length,
            &torrent_info.piece_hashes
        );

        fs::write(output_file, &piece_data).unwrap();
        println!("Piece {} downloaded to {}.", piece_index, output_file);
    } else if command == "handshake" {
        let torrent_file = &args[2];
        let peer_addr = &args[3];

        let torrent_info = parse_torrent_file(torrent_file);
        let mut stream = TcpStream::connect(peer_addr).unwrap();
        let peer_id = perform_handshake(&mut stream, &torrent_info.info_hash);

        println!("Peer ID: {}", hex::encode(peer_id));
    } else if command == "magnet_parse" {
        let magnet_link = &args[2];
        let magnet_info = parse_magnet_link(magnet_link);

        println!("Tracker URL: {}", magnet_info.tracker_url);
        println!("Info Hash: {}", magnet_info.info_hash);
    } else if command == "magnet_handshake" {
        let magnet_link = &args[2];
        let magnet_info = parse_magnet_link(magnet_link);

        // Get peers from tracker
        let peers = get_peers_from_magnet(&magnet_info);
        let peer_addr = &peers[0]; // Use first peer

        // Convert hex info hash to bytes
        let info_hash_bytes = hex_to_bytes(&magnet_info.info_hash);

        // Perform handshake with extension support
        let mut stream = TcpStream::connect(peer_addr).unwrap();
        let (peer_id, peer_supports_extensions) = perform_handshake_with_extensions(&mut stream, &info_hash_bytes, true);

        // Exchange messages (bitfield, extension handshake if supported, interested, unchoke)
        let peer_metadata_extension_id = exchange_messages_with_extensions(&mut stream, peer_supports_extensions);

        println!("Peer ID: {}", hex::encode(peer_id));
        if let Some(extension_id) = peer_metadata_extension_id {
            println!("Peer Metadata Extension ID: {}", extension_id);
        }
    } else {
        println!("unknown command: {}", args[1])
    }
}
