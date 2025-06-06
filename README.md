![MIT License](https://img.shields.io/badge/license-MIT-blue.svg)

# rust-ids 🛡️

A simple network intrusion detection system (IDS) written in Rust that monitors unusual port scanning behavior on a specified network interface.

***Note: All timestamps in logs and output are in UTC ⏰  
Adjust accordingly for your local timezone (e.g., CST = UTC−5 during Daylight Saving Time).

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
git clone https://github.com/havocst/rust-ids.git
cd rust-ids
cargo build --release
```

Grant the binary the necessary network permissions (so you don't need to run it as root):

```bash
sudo setcap cap_net_raw,cap_net_admin=eip ./target/release/rust-ids
```

---

## Running the IDS 🚦

### Basic usage (uses defaults)
```bash
./target/release/rust-ids --iface wlo1
```
- Uses defaults: `threshold=20`, `window=60`, `log-file=alerts.log`
- Replace `wlo1` with your network interface name.

### Advanced usage (custom threshold, window, and log file)
```bash
./target/release/rust-ids --iface wlo1 --threshold 25 --window 60 --log-file alerts.log
```
- Customize detection threshold, window, and log file as needed.

---

## Granting Network Permissions 🔐

Because `rust-ids` needs to capture raw packets, it requires special permissions. The recommended way is:

```bash
sudo setcap cap_net_raw,cap_net_admin=eip ./target/release/rust-ids
```

This allows the binary to capture packets without running the entire program as root, improving security.

---

## Logs 📄

Alerts are logged to the file you specify with `--log-file`. Example alert:

```
[2025-06-02 17:38:33] Alert: Port scan detected from 192.168.1.10 - 30 ports scanned in 60s
```

---

## Testing ✅

Run the tests with:

```bash
cargo test
```

Make sure you have the development dependencies installed.

---

## Contributing 🤝

Contributions, issues, and feature requests are welcome!

Feel free to fork the repo and submit pull requests.

Please follow the Rust formatting and style guidelines.

---

## License 📜

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

Thank you for using rust-ids! Stay safe and secure! 🔒✨
