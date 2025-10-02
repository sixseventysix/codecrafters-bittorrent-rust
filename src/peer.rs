use std::net::TcpStream;
use std::io::{Write, Read};
use sha1::{Sha1, Digest};

use crate::tracker::PEER_ID;

pub const BLOCK_SIZE: i64 = 16 * 1024;

/// Perform handshake with peer
pub fn perform_handshake(stream: &mut TcpStream, info_hash: &[u8]) -> [u8; 20] {
    let (peer_id, _) = perform_handshake_with_extensions(stream, info_hash, false);
    peer_id
}

/// Perform handshake with peer, optionally with extension support
/// Returns (peer_id, peer_supports_extensions)
pub fn perform_handshake_with_extensions(stream: &mut TcpStream, info_hash: &[u8], support_extensions: bool) -> ([u8; 20], bool) {
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

/// Exchange initial peer messages (bitfield, interested, unchoke)
pub fn exchange_initial_messages(stream: &mut TcpStream) {
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

/// Download a single piece from peer
pub fn download_piece_from_peer(
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
