use std::net::TcpStream;
use std::io::{Write, Read};
use serde_bencode;
use anyhow::{Result, Context, anyhow};

/// Send extension handshake message
pub fn send_extension_handshake(stream: &mut TcpStream) -> Result<()> {
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

    let bencoded_dict = serde_bencode::to_bytes(&extension_dict)
        .context("Failed to encode extension handshake")?;

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

    stream.write_all(&extension_handshake)
        .context("Failed to send extension handshake")?;

    Ok(())
}

/// Receive and parse extension handshake message
/// Returns the peer's extension ID for ut_metadata
pub fn receive_extension_handshake(stream: &mut TcpStream) -> Result<i64> {
    // Read message length
    let mut length_prefix = [0u8; 4];
    stream.read_exact(&mut length_prefix)
        .context("Failed to read extension handshake length")?;
    let msg_length = u32::from_be_bytes(length_prefix);

    // Read message
    let mut message = vec![0u8; msg_length as usize];
    stream.read_exact(&mut message)
        .context("Failed to read extension handshake message")?;

    // Check message ID (should be 20 for extension protocol)
    if message[0] != 20 {
        return Err(anyhow!("Expected extension message (ID 20), got {}", message[0]));
    }

    // Check extension message ID (should be 0 for handshake)
    if message[1] != 0 {
        return Err(anyhow!("Expected extension handshake (ID 0), got {}", message[1]));
    }

    // Parse bencoded dictionary from payload (starting at index 2)
    let dict_bytes = &message[2..];
    let extension_dict: serde_bencode::value::Value =
        serde_bencode::from_bytes(dict_bytes)
            .context("Failed to parse extension handshake dictionary")?;

    // Extract ut_metadata extension ID from {"m": {"ut_metadata": <ID>}}
    if let serde_bencode::value::Value::Dict(dict) = extension_dict {
        if let Some(serde_bencode::value::Value::Dict(m_dict)) = dict.get(b"m".as_ref()) {
            if let Some(serde_bencode::value::Value::Int(id)) = m_dict.get(b"ut_metadata".as_ref()) {
                return Ok(*id);
            }
        }
    }

    Err(anyhow!("Peer does not support ut_metadata extension"))
}

/// Send metadata request message
pub fn send_metadata_request(stream: &mut TcpStream, peer_metadata_extension_id: i64, piece_index: i64) -> Result<()> {
    // Create bencoded dictionary: {"msg_type": 0, "piece": 0}
    let request_dict = serde_bencode::value::Value::Dict(
        vec![
            (b"msg_type".to_vec(), serde_bencode::value::Value::Int(0)),
            (b"piece".to_vec(), serde_bencode::value::Value::Int(piece_index)),
        ].into_iter().collect()
    );

    let bencoded_dict = serde_bencode::to_bytes(&request_dict)
        .context("Failed to encode metadata request")?;

    // Build metadata request message
    let mut metadata_request = Vec::new();

    // Message length = 1 (message id = 20) + 1 (peer's extension id) + bencoded dict length
    let message_length = 1 + 1 + bencoded_dict.len();
    metadata_request.extend_from_slice(&(message_length as u32).to_be_bytes());

    // Message ID for extension protocol is 20
    metadata_request.push(20u8);

    // Extension message ID (peer's ut_metadata ID)
    metadata_request.push(peer_metadata_extension_id as u8);

    // Bencoded dictionary
    metadata_request.extend_from_slice(&bencoded_dict);

    stream.write_all(&metadata_request)
        .context("Failed to send metadata request")?;

    Ok(())
}

/// Receive metadata data message
/// Returns the metadata bytes
pub fn receive_metadata(stream: &mut TcpStream) -> Result<Vec<u8>> {
    // Read message length
    let mut length_prefix = [0u8; 4];
    stream.read_exact(&mut length_prefix)
        .context("Failed to read metadata response length")?;
    let msg_length = u32::from_be_bytes(length_prefix);

    // Read message
    let mut message = vec![0u8; msg_length as usize];
    stream.read_exact(&mut message)
        .context("Failed to read metadata response message")?;

    // Check message ID (should be 20 for extension protocol)
    if message[0] != 20 {
        return Err(anyhow!("Expected extension message (ID 20), got {}", message[0]));
    }

    // Extension message ID is at index 1 (peer's ut_metadata ID)
    // Payload starts at index 2
    let payload = &message[2..];

    // Parse the bencoded dictionary to validate it and get total_size
    let metadata_dict: serde_bencode::value::Value = serde_bencode::from_bytes(payload)
        .context("Failed to parse metadata response dictionary")?;

    // Validate it's a data message (msg_type: 1)
    if let serde_bencode::value::Value::Dict(dict) = &metadata_dict {
        if let Some(serde_bencode::value::Value::Int(msg_type)) = dict.get(b"msg_type".as_ref()) {
            if *msg_type != 1 {
                return Err(anyhow!("Expected data message (msg_type 1), got {}", msg_type));
            }
        }

        // Get the total_size to know how much metadata to expect
        if let Some(serde_bencode::value::Value::Int(total_size)) = dict.get(b"total_size".as_ref()) {
            // The metadata piece is at the end, with length = total_size
            let metadata_start = payload.len() - (*total_size as usize);
            return Ok(payload[metadata_start..].to_vec());
        }
    }

    Err(anyhow!("Failed to parse metadata response"))
}
