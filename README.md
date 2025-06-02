# 🛡️ rust-IDS

![Rust](https://img.shields.io/badge/Rust-2021-orange)
![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)

A lightweight and efficient Intrusion Detection System (IDS) written in Rust for detecting **port scanning behavior** on local networks. It listens to raw packets, tracks incoming connection attempts, and alerts when a single IP probes too many ports within a defined time window.

---

## 🔍 Features

- 🔎 Detects basic TCP port scans (e.g., Nmap)
- ⚙️ Configurable detection thresholds and interface
- 🕐 Time-based sliding window detection logic
- 🧪 Simple CLI interface (no root setup required beyond execution)
- 🖥️ Built-in console alerts with timestamps
- 🪶 Small and fast — ideal for learning and lightweight use cases

---

## 🚀 Quick Start

### ✅ Requirements

- Rust (latest stable)  
- Linux or macOS (for raw socket support)  
- Admin privileges to run

---

### 🧱 Build

```bash
git clone https://github.com/havocst/rust-IDS.git
cd rust-IDS
cargo build --release
