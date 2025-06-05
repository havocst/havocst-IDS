use std::collections::{HashMap, HashSet};
use std::fs::OpenOptions;
use std::io::Write;
use std::net::Ipv4Addr;
use std::process;
use std::time::{Duration, Instant};

use chrono::Utc;
use clap::Parser;
use pnet::datalink::{self, Channel::Ethernet, Config};
use pnet::packet::{ethernet::EthernetPacket, ip::IpNextHeaderProtocols, ipv4::Ipv4Packet, tcp::TcpPacket, Packet};

// Rodio-related imports for sound playback
use std::fs::File;
use std::io::BufReader;
use rodio::{Decoder, OutputStream, Sink};

// For alert rate-limiting
use std::sync::Mutex;
use once_cell::sync::Lazy;

#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {
    /// Network interface to monitor
    #[arg(short, long)]
    iface: String,

    /// Number of unique ports to trigger alert
    #[arg(short, long, default_value_t = 25)]
    threshold: usize,

    /// Time window in seconds
    #[arg(short, long, default_value_t = 60)]
    window: u64,

    /// File to log alerts
    #[arg(short, long, default_value = "alerts.log")]
    log_file: String,
}

struct IpActivity {
    ports: HashSet<u16>,
    first_seen: Instant,
}

fn log_alert(path: &str, message: &str) {
    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(path) {
        let _ = writeln!(file, "{}", message);
    }
}

// Static for rate-limiting the alert sound to once every 15 seconds
static LAST_ALERT: Lazy<Mutex<Instant>> = Lazy::new(|| Mutex::new(Instant::now() - Duration::from_secs(15)));

/// Plays an alert sound from 'alert.wav' in the root directory asynchronously,
/// but only if at least 15 seconds have passed since the last alert.
fn maybe_play_alert_sound() {
    let mut last = LAST_ALERT.lock().unwrap();
    if last.elapsed() > Duration::from_secs(15) {
        if let Ok((_stream, stream_handle)) = OutputStream::try_default() {
            if let Ok(file) = File::open("alert.wav") {
                if let Ok(source) = Decoder::new(BufReader::new(file)) {
                    if let Ok(sink) = Sink::try_new(&stream_handle) {
                        sink.append(source);
                        sink.detach(); // Play asynchronously, do not block
                    }
                }
            }
        }
        *last = Instant::now();
    }
}

fn main() {
    let args = Args::parse();

    println!(
        "[{}] Starting rust-ids on interface '{}' with threshold={} ports, window={}s",
        Utc::now().format("%Y-%m-%d %H:%M:%S"),
        args.iface,
        args.threshold,
        args.window
    );

    let interfaces = datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .find(|iface| iface.name == args.iface)
        .unwrap_or_else(|| {
            eprintln!("❌ Interface '{}' not found", args.iface);
            process::exit(1);
        });

    let mut config = Config::default();
    config.read_timeout = Some(Duration::from_millis(1000));

    let (_, mut rx) = match datalink::channel(&interface, config) {
        Ok(Ethernet(_tx, rx)) => (_tx, rx),
        Ok(_) => {
            eprintln!("❌ Unsupported channel type");
            process::exit(1);
        }
        Err(e) => {
            eprintln!("❌ Failed to create datalink channel: {}", e);
            process::exit(1);
        }
    };

    let mut ip_map: HashMap<Ipv4Addr, IpActivity> = HashMap::new();
    let window_duration = Duration::from_secs(args.window);
    let mut last_heartbeat = Instant::now();

    loop {
        match rx.next() {
            Ok(packet_data) => {
                if let Some(ethernet) = EthernetPacket::new(packet_data) {
                    if ethernet.get_ethertype() == pnet::packet::etherTypes::Ipv4 {
                        let ipv4_payload = ethernet.payload();
                        if ipv4_payload.len() >= Ipv4Packet::minimum_packet_size() {
                            if let Some(ipv4) = Ipv4Packet::new(ipv4_payload) {
                                if ipv4.get_next_level_protocol() == IpNextHeaderProtocols::Tcp {
                                    let ip_header_len = ipv4.get_header_length() as usize * 4;
                                    if ipv4_payload.len() < ip_header_len {
                                        eprintln!(
                                            "⚠️ IPv4 payload too short: {} bytes, expected at least {} bytes",
                                            ipv4_payload.len(),
                                            ip_header_len
                                        );
                                        continue;
                                    }

                                    let tcp_payload = &ipv4_payload[ip_header_len..];
                                    if tcp_payload.len() < TcpPacket::minimum_packet_size() {
                                        eprintln!(
                                            "⚠️ TCP payload too short: {} bytes, expected at least {} bytes",
                                            tcp_payload.len(),
                                            TcpPacket::minimum_packet_size()
                                        );
                                        continue;
                                    }

                                    match TcpPacket::new(tcp_payload) {
                                        Some(tcp) => {
                                            let source_ip = ipv4.get_source();
                                            let now = Instant::now();

                                            // Remove expired activity entries
                                            ip_map.retain(|_, activity| {
                                                now.duration_since(activity.first_seen) <= window_duration
                                            });

                                            let activity = ip_map.entry(source_ip).or_insert_with(|| IpActivity {
                                                ports: HashSet::new(),
                                                first_seen: now,
                                            });

                                            activity.ports.insert(tcp.get_destination());

                                            if activity.ports.len() >= args.threshold {
                                                let alert_msg = format!(
                                                    "[{}] ⚠️ Potential port scan from {}: {} ports in {}s",
                                                    Utc::now().format("%Y-%m-%d %H:%M:%S"),
                                                    source_ip,
                                                    activity.ports.len(),
                                                    args.window
                                                );
                                                println!("{}", alert_msg);
                                                log_alert(&args.log_file, &alert_msg);
                                                maybe_play_alert_sound(); // Play the .wav alert sound asynchronously (rate-limited)
                                                ip_map.remove(&source_ip);
                                            }
                                        }
                                        None => {
                                            eprintln!("⚠️ Failed to parse TCP packet.");
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                if last_heartbeat.elapsed() >= Duration::from_secs(30) {
                    println!("[{}] ✅ IDS still running...", Utc::now().format("%Y-%m-%d %H:%M:%S"));
                    last_heartbeat = Instant::now();
                }
            }
            Err(_) => {
                // Timeout occurred, check for heartbeat
                if last_heartbeat.elapsed() >= Duration::from_secs(30) {
                    println!("[{}] ✅ IDS still running...", Utc::now().format("%Y-%m-%d %H:%M:%S"));
                    last_heartbeat = Instant::now();
                }
            }
        }
    }
}
