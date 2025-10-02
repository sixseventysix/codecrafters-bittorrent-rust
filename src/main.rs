mod bencode;
mod torrent;
mod tracker;
mod peer;
mod extension;
mod magnet;

use std::fs;
use std::net::TcpStream;
use std::io::Read;
use sha1::{Sha1, Digest};
use clap::{Parser, Subcommand};

use bencode::decode_bencoded_value;
use torrent::parse_torrent_file;
use tracker::{get_peers_from_tracker, get_peers_from_magnet};
use peer::{perform_handshake, perform_handshake_with_extensions, exchange_initial_messages, download_piece_from_peer};
use extension::{send_extension_handshake, receive_extension_handshake, send_metadata_request, receive_metadata};
use magnet::parse_magnet_link;

#[derive(Parser)]
#[command(name = "bittorrent")]
#[command(about = "A BitTorrent client", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Decode a bencoded value
    Decode {
        /// Bencoded string to decode
        value: String,
    },
    /// Show torrent file information
    Info {
        /// Path to torrent file
        torrent: String,
    },
    /// List peers for a torrent
    Peers {
        /// Path to torrent file
        torrent: String,
    },
    /// Perform handshake with a peer
    Handshake {
        /// Path to torrent file
        torrent: String,
        /// Peer address (ip:port)
        peer: String,
    },
    /// Download a single piece
    #[command(name = "download_piece")]
    DownloadPiece {
        /// Output file path
        #[arg(short, long)]
        output: String,
        /// Path to torrent file
        torrent: String,
        /// Piece index
        piece: usize,
    },
    /// Download entire file
    Download {
        /// Output file path
        #[arg(short, long)]
        output: String,
        /// Path to torrent file
        torrent: String,
    },
    /// Parse a magnet link
    #[command(name = "magnet_parse")]
    MagnetParse {
        /// Magnet link
        magnet_link: String,
    },
    /// Perform handshake using magnet link
    #[command(name = "magnet_handshake")]
    MagnetHandshake {
        /// Magnet link
        magnet_link: String,
    },
    /// Get torrent info from magnet link
    #[command(name = "magnet_info")]
    MagnetInfo {
        /// Magnet link
        magnet_link: String,
    },
    /// Download a single piece using magnet link
    #[command(name = "magnet_download_piece")]
    MagnetDownloadPiece {
        /// Output file path
        #[arg(short, long)]
        output: String,
        /// Magnet link
        magnet_link: String,
        /// Piece index
        piece: usize,
    },
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Decode { value } => {
            let decoded_value = decode_bencoded_value(&value);
            println!("{}", decoded_value.to_string());
        }

        Commands::Info { torrent } => {
            let torrent_info = parse_torrent_file(&torrent);
            println!("Tracker URL: {}", torrent_info.tracker_url);
            println!("Length: {}", torrent_info.length);
            println!("Info Hash: {}", hex::encode(&torrent_info.info_hash));
            println!("Piece Length: {}", torrent_info.piece_length);
            println!("Piece Hashes:");
            for chunk in torrent_info.piece_hashes.chunks(20) {
                println!("{}", hex::encode(chunk));
            }
        }

        Commands::Peers { torrent } => {
            let torrent_info = parse_torrent_file(&torrent);
            let peers = get_peers_from_tracker(&torrent_info);
            for peer in peers {
                println!("{}", peer);
            }
        }

        Commands::Handshake { torrent, peer } => {
            let torrent_info = parse_torrent_file(&torrent);
            let mut stream = TcpStream::connect(&peer).unwrap();
            let peer_id = perform_handshake(&mut stream, &torrent_info.info_hash);
            println!("Peer ID: {}", hex::encode(peer_id));
        }

        Commands::DownloadPiece { output, torrent, piece } => {
            let torrent_info = parse_torrent_file(&torrent);
            let peers = get_peers_from_tracker(&torrent_info);
            let peer_addr = &peers[0];

            let mut stream = TcpStream::connect(peer_addr).unwrap();
            perform_handshake(&mut stream, &torrent_info.info_hash);
            exchange_initial_messages(&mut stream);

            let piece_data = download_piece_from_peer(
                &mut stream,
                piece,
                torrent_info.piece_length,
                torrent_info.length,
                &torrent_info.piece_hashes
            );

            fs::write(&output, &piece_data).unwrap();
            println!("Piece {} downloaded to {}.", piece, output);
        }

        Commands::Download { output, torrent } => {
            let torrent_info = parse_torrent_file(&torrent);
            let peers = get_peers_from_tracker(&torrent_info);
            let peer_addr = &peers[0];

            let mut stream = TcpStream::connect(peer_addr).unwrap();
            perform_handshake(&mut stream, &torrent_info.info_hash);
            exchange_initial_messages(&mut stream);

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

            fs::write(&output, &file_data).unwrap();
            println!("Downloaded {} to {}.", torrent, output);
        }

        Commands::MagnetParse { magnet_link } => {
            let magnet_info = parse_magnet_link(&magnet_link);
            println!("Tracker URL: {}", magnet_info.tracker_url);
            println!("Info Hash: {}", magnet_info.info_hash);
        }

        Commands::MagnetHandshake { magnet_link } => {
            let magnet_info = parse_magnet_link(&magnet_link);
            let peers = get_peers_from_magnet(&magnet_info);
            let peer_addr = &peers[0];
            let info_hash_bytes = hex::decode(&magnet_info.info_hash).unwrap();

            let mut stream = TcpStream::connect(peer_addr).unwrap();
            let (peer_id, peer_supports_extensions) = perform_handshake_with_extensions(&mut stream, &info_hash_bytes, true);

            println!("Peer ID: {}", hex::encode(peer_id));

            if peer_supports_extensions {
                let mut length_prefix = [0u8; 4];
                stream.read_exact(&mut length_prefix).unwrap();
                let msg_length = u32::from_be_bytes(length_prefix);
                let mut message = vec![0u8; msg_length as usize];
                stream.read_exact(&mut message).unwrap();

                send_extension_handshake(&mut stream);

                if let Some(extension_id) = receive_extension_handshake(&mut stream) {
                    println!("Peer Metadata Extension ID: {}", extension_id);
                }
            }
        }

        Commands::MagnetInfo { magnet_link } => {
            let magnet_info = parse_magnet_link(&magnet_link);
            let peers = get_peers_from_magnet(&magnet_info);
            let peer_addr = &peers[0];
            let info_hash_bytes = hex::decode(&magnet_info.info_hash).unwrap();

            let mut stream = TcpStream::connect(peer_addr).unwrap();
            let (_, peer_supports_extensions) = perform_handshake_with_extensions(&mut stream, &info_hash_bytes, true);

            if !peer_supports_extensions {
                eprintln!("Peer doesn't support extensions");
                return;
            }

            let mut length_prefix = [0u8; 4];
            stream.read_exact(&mut length_prefix).unwrap();
            let msg_length = u32::from_be_bytes(length_prefix);
            let mut message = vec![0u8; msg_length as usize];
            stream.read_exact(&mut message).unwrap();

            send_extension_handshake(&mut stream);

            let peer_metadata_extension_id = receive_extension_handshake(&mut stream)
                .expect("Failed to get metadata extension ID");

            send_metadata_request(&mut stream, peer_metadata_extension_id, 0);

            let metadata_bytes = receive_metadata(&mut stream);

            let info_dict: serde_bencode::value::Value =
                serde_bencode::from_bytes(&metadata_bytes).unwrap();

            let mut hasher = Sha1::new();
            hasher.update(&metadata_bytes);
            let calculated_info_hash = hasher.finalize();
            let calculated_info_hash_hex = hex::encode(calculated_info_hash);

            if calculated_info_hash_hex != magnet_info.info_hash {
                eprintln!("Info hash mismatch! Expected: {}, Got: {}",
                    magnet_info.info_hash, calculated_info_hash_hex);
            }

            if let serde_bencode::value::Value::Dict(info) = info_dict {
                println!("Tracker URL: {}", magnet_info.tracker_url);

                if let Some(serde_bencode::value::Value::Int(length)) = info.get(b"length".as_ref()) {
                    println!("Length: {}", length);
                }

                println!("Info Hash: {}", magnet_info.info_hash);

                if let Some(serde_bencode::value::Value::Int(piece_length)) = info.get(b"piece length".as_ref()) {
                    println!("Piece Length: {}", piece_length);
                }

                if let Some(serde_bencode::value::Value::Bytes(pieces)) = info.get(b"pieces".as_ref()) {
                    println!("Piece Hashes:");
                    for chunk in pieces.chunks(20) {
                        println!("{}", hex::encode(chunk));
                    }
                }
            }
        }

        Commands::MagnetDownloadPiece { output, magnet_link, piece } => {
            let magnet_info = parse_magnet_link(&magnet_link);
            let peers = get_peers_from_magnet(&magnet_info);
            let peer_addr = &peers[0];
            let info_hash_bytes = hex::decode(&magnet_info.info_hash).unwrap();

            let mut stream = TcpStream::connect(peer_addr).unwrap();
            let (_, peer_supports_extensions) = perform_handshake_with_extensions(&mut stream, &info_hash_bytes, true);

            if !peer_supports_extensions {
                eprintln!("Peer doesn't support extensions");
                return;
            }

            // Read and discard the bitfield message
            let mut length_prefix = [0u8; 4];
            stream.read_exact(&mut length_prefix).unwrap();
            let msg_length = u32::from_be_bytes(length_prefix);
            let mut message = vec![0u8; msg_length as usize];
            stream.read_exact(&mut message).unwrap();

            send_extension_handshake(&mut stream);

            let peer_metadata_extension_id = receive_extension_handshake(&mut stream)
                .expect("Failed to get metadata extension ID");

            send_metadata_request(&mut stream, peer_metadata_extension_id, 0);

            let metadata_bytes = receive_metadata(&mut stream);

            let info_dict: serde_bencode::value::Value =
                serde_bencode::from_bytes(&metadata_bytes).unwrap();

            if let serde_bencode::value::Value::Dict(info) = info_dict {
                let length = if let Some(serde_bencode::value::Value::Int(l)) = info.get(b"length".as_ref()) {
                    *l
                } else {
                    eprintln!("Failed to get file length from metadata");
                    return;
                };

                let piece_length = if let Some(serde_bencode::value::Value::Int(pl)) = info.get(b"piece length".as_ref()) {
                    *pl
                } else {
                    eprintln!("Failed to get piece length from metadata");
                    return;
                };

                let piece_hashes = if let Some(serde_bencode::value::Value::Bytes(pieces)) = info.get(b"pieces".as_ref()) {
                    pieces.clone()
                } else {
                    eprintln!("Failed to get piece hashes from metadata");
                    return;
                };

                // Now exchange initial messages and download the piece
                exchange_initial_messages(&mut stream);

                let piece_data = download_piece_from_peer(
                    &mut stream,
                    piece,
                    piece_length,
                    length,
                    &piece_hashes
                );

                fs::write(&output, &piece_data).unwrap();
                println!("Piece {} downloaded to {}.", piece, output);
            }
        }
    }
}
