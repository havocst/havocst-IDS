use clap::Parser;
use chrono::Utc;
use pnet::datalink::{self, Channel::Ethernet, NetworkInterface};
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::Packet;
use std::collections::{HashMap, HashSet};
use std::fs::OpenOptions;
use std::io::Write;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

/// Simple Rust IDS to detect TCP port scans.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Number of unique ports scanned within window to trigger alert
    #[arg(short, long, default_value_t = 20)]
    threshold: usize,

    /// Time window in seconds to count unique ports
    #[arg(short, long, default_value_t = 60)]
    window: u64,

    /// Optional file path to log alerts
    #[arg(short, long)]
    log_file: Option<String>,
}

struct IpActivity {
    ports: HashSet<u16>,
    first_seen: Instant,
}

fn log_alert(log_file: &Option<String>, alert: &str) {
    if let Some(path) = log_file {
        match OpenOptions::new().append(true).create(true).open(path) {
            Ok(mut file) => {
                if let Err(e) = writeln!(file, "{}", alert) {
                    eprintln!("Failed to write to log file: {}", e);
                }
            }
            Err(e) => eprintln!("Failed to open log file '{}': {}", path, e),
        }
    }
}

fn get_default_interface() -> Option<NetworkInterface> {
    datalink::interfaces()
        .into_iter()
        .find(|iface| iface.is_up() && !iface.is_loopback() && !iface.ips.is_empty())
}

fn main() {
    // Enable backtrace for better error debugging (optional)
    std::env::set_var("RUST_BACKTRACE", "1");

    let args = Args::parse();

    let interface = get_default_interface().unwrap_or_else(|| {
        eprintln!("❌ No suitable network interface found (up, non-loopback, has IPs).");
        std::process::exit(1);
    });

    println!(
        "[{}] ✅ Starting rust-IDS on interface '{}' with threshold={} ports, window={}s",
        Utc::now().format("%Y-%m-%d %H:%M:%S"),
        interface.name,
        args.threshold,
        args.window
    );

    let (_, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(_tx, rx)) => (_tx, rx),
        Ok(_) => {
            eprintln!("❌ Unhandled channel type");
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("❌ Failed to create datalink channel: {}", e);
            std::process::exit(1);
        }
    };

    let mut ip_map: HashMap<Ipv4Addr, IpActivity> = HashMap::new();
    let window_duration = Duration::from_secs(args.window);
    let mut last_heartbeat = Instant::now();

    loop {
        match rx.next() {
            Ok(packet_data) => {
                if let Some(ethernet) = EthernetPacket::new(packet_data) {
                    if ethernet.get_ethertype() == pnet::packet::ethernet::EtherTypes::Ipv4 {
                        if let Some(ipv4) = Ipv4Packet::new(ethernet.payload()) {
                            if ipv4.get_next_level_protocol() == IpNextHeaderProtocols::Tcp {
                                // Defensive check: Only parse TCP packet if payload length is valid
                                let ipv4_payload = ipv4.payload();
                                if ipv4_payload.len() >= TcpPacket::minimum_packet_size() {
                                    if let Some(tcp) = TcpPacket::new(ipv4_payload) {
                                        let source_ip = ipv4.get_source();
                                        let now = Instant::now();

                                        // Remove old entries outside the window
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
                                                "[{}] ⚠️  Potential port scan from {}: {} ports in {}s",
                                                Utc::now().format("%Y-%m-%d %H:%M:%S"),
                                                source_ip,
                                                activity.ports.len(),
                                                args.window
                                            );
                                            println!("{}", alert_msg);
                                            log_alert(&args.log_file, &alert_msg);
                                            ip_map.remove(&source_ip);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            Err(e) => eprintln!("❌ Failed to read packet: {}", e),
        }

        if last_heartbeat.elapsed() >= Duration::from_secs(30) {
            println!(
                "[{}] ✅ IDS still running...",
                Utc::now().format("%Y-%m-%d %H:%M:%S")
            );
            last_heartbeat = Instant::now();
        }
    }
}
