# rust-IDS 🛡️

A simple network intrusion detection system (IDS) written in Rust that monitors unusual port scanning behavior on a specified network interface.

## Features 🚀

- 🕵️‍♂️ Monitors TCP traffic on a specified network interface.
- ⚠️ Detects IPs scanning more than a threshold number of distinct destination ports within a sliding time window.
- 📝 Logs alerts to a file.
- 🦀 Efficient and lightweight with Rust's safety and performance.

## Requirements ✅

- 🦀 Rust toolchain ([install rustup](https://rustup.rs/))
- 🖥️ Linux or compatible Unix-like system with raw socket permissions
- 🌐 Network interface to monitor (e.g., `wlo1`, `eth0`)

## Build 🛠️

Clone the repo and build in release mode for better performance:

```bash
git clone https://github.com/havocst/rust-IDS.git
cd rust-IDS
cargo build --release
