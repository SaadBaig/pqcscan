<p align="center">
  <img src="images/pqcscan.jpg" alt="...">
</p>


*Scan SSH/TLS servers for PQC support, validate real handshake behavior, and assess quantum risk*

> **Fork note:** This fork extends [pqcscan](https://github.com/anvilsecure/pqcscan) by Anvil Secure with full TLS handshake validation, downgrade attack detection, quantum risk assessment, SCSV fallback testing, and X.509 certificate analysis. It goes beyond checking what servers advertise to validating what they actually negotiate — and flags whether captured traffic is decryptable by a future quantum computer.

## Table of Contents

- [Installation](#installation)
- [Usage](#usage)
  - [Quick Scan](#quick-scan-advertisement-detection)
  - [Full Handshake Validation with Risk Assessment](#full-handshake-validation-with-risk-assessment)
  - [Example Output](#example-output)
  - [All Options](#all-options)
- [What PQCscan does](#what-pqcscan-does)
  - [Advertisement Detection](#advertisement-detection-default)
  - [Full Handshake Validation](#full-handshake-validation---validate-handshake)
  - [Risk Assessment](#risk-assessment)
- [Validated PQC Algorithms](#validated-pqc-algorithms)
- [How It Works](#how-it-works)
- [Contributing](#contributing)

---

# Installation

## Binary Releases
Binary releases for Linux, macOS, and Windows are available on the [releases](https://github.com/anvilsecure/pqcscan/releases) page.

## Building from Source

Requires Rust 1.83 or later (for rustls compatibility).

```
git clone https://github.com/anvilsecure/pqcscan.git
cd pqcscan
cargo build --release
./target/release/pqcscan --help
```

---

# Usage

## Quick Scan (Advertisement Detection)

```bash
# Scan a single TLS target
pqcscan tls-scan -t cloudflare.com

# Scan a single SSH target
pqcscan ssh-scan -t github.com

# Scan from a target list with JSON output
pqcscan tls-scan -T targets.txt -o results.json
```

## Full Handshake Validation with Risk Assessment

```bash
pqcscan tls-scan -t cloudflare.com --validate-handshake
```

This performs three real handshakes, tests SCSV fallback signaling, parses the server certificate, and produces a risk rating.

## Example Output

```
$ pqcscan tls-scan -t cloudflare.com --validate-handshake

═══════════════════════════════════════════════════════════════
  PQCscan Summary
═══════════════════════════════════════════════════════════════

  Scanned cloudflare.com:443 in 5.05s

  ┌─ cloudflare.com:443 (TLS)
  │
  │  🟡 Risk Assessment: MEDIUM
  │  ✅ PQC Key Exchange: X25519MLKEM768 (TLS 1.3)
  │  ✅ TLS Fallback SCSV: Supported
  │  ⚠️  Vulnerable key exchange algorithms:
  │        - ECDHE (TLS 1.2)
  │        - X25519 (TLS 1.3)
  │  ⚠️  Vulnerable certificate algorithms:
  │        - ECDSA-P-256
  │
  │  🔧 Remediation:
  │     Key Exchange:
  │        - Plan TLS 1.2 deprecation per NIST SP 800-52 Rev. 2
  │     Certificates:
  │        - Adopt ML-DSA certificates when available
  └────────────────────────────────────────

═══════════════════════════════════════════════════════════════
```

## All Options

```
pqcscan --help
```

Key flags for `tls-scan`:
- `-t HOST:PORT` — single target (port 443 is default)
- `-T FILE` — target list (one per line, `#` comments supported)
- `-o FILE` — JSON output
- `--csv FILE` — CSV output
- `--xml FILE` — XML output
- `--report FILE` — HTML report output
- `--validate-handshake` — full handshake validation + risk assessment
- `--only-hybrid-algos` — limit to hybrid PQC algorithms
- `--test-nonpqc-algos` — also test classical groups
- `--num-threads N` — parallel scan threads (default: 8)

Key flags for `ssh-scan`:
- `-t HOST:PORT` — single target (port 22 is default)
- `-T FILE` — target list
- `-o FILE` — JSON output
- `--report FILE` — HTML report output
- `--num-threads N` — parallel scan threads (default: 8)

Verbose logging: `RUST_LOG=debug pqcscan tls-scan -t example.com --validate-handshake`

---

# What PQCscan does

**pqcscan** scans SSH and TLS servers for post-quantum cryptography support.

### Advertisement Detection (default)
Sends raw TLS ClientHello messages to probe which PQC key exchange groups a server accepts. Parses the ServerHello to extract the negotiated cipher suite, key exchange group, TLS version, and detects HelloRetryRequests (RFC 8446). For SSH, reads the server's `SSH_MSG_KEXINIT` to identify PQC KEX algorithms.

### Full Handshake Validation (`--validate-handshake`)
Completes three real TLS handshakes per target using [rustls](https://github.com/rustls/rustls):

1. **PQC-only** (TLS 1.3) — offers only PQC key exchange groups; if the server doesn't support PQC, the handshake fails
2. **Classical-only** (TLS 1.3) — excludes all PQC groups to test fallback behavior
3. **TLS 1.2 probe** — tests whether the server accepts the legacy protocol

Each handshake goes through the full lifecycle: key exchange, encrypted extensions, certificate exchange, and Finished messages. The tool also tests [TLS_FALLBACK_SCSV](https://www.rfc-editor.org/rfc/rfc7507) (RFC 7507) to check if the server detects version downgrade attempts.

### Risk Assessment
Compares handshake results to detect **downgrade attacks** (server chose classical when PQC was offered) and runs a quantum risk assessment. The overall rating uses a 5-tier severity scale:

| Rating | Icon | Meaning |
|---|---|---|
| CRITICAL | 🔴 | No PQC — all traffic is quantum-decryptable |
| HIGH | 🟠 | PQC advertised but not negotiated, or active downgrade risk |
| MEDIUM | 🟡 | PQC active, residual classical concerns (TLS 1.2 fallback, classical certificates) |
| LOW | 🟢 | PQC active, no TLS 1.2 fallback, minor concerns only |
| INFO | ✅ | Fully quantum-safe (theoretical — requires ML-DSA certificates) |

X.509 certificates are parsed to extract key type (RSA, ECDSA-P-256, Ed25519), key size, and validity period. Certificate findings are capped at MEDIUM when PQC key exchange is active — cert forgery requires an active MitM, not passive harvest. SSH servers get their own risk assessment based on advertised KEX algorithms and classical fallback risk.

---

# Validated PQC Algorithms

The tool covers all NIST FIPS 203 (ML-KEM) key exchange variants deployed in TLS today:

| Algorithm | Type |
|---|---|
| ML-KEM-512 | Standalone |
| ML-KEM-768 | Standalone |
| ML-KEM-1024 | Standalone |
| X25519MLKEM768 | Hybrid (X25519 + ML-KEM-768) |
| SECP256R1MLKEM768 | Hybrid (P-256 + ML-KEM-768) |
| SECP384R1MLKEM1024 | Hybrid (P-384 + ML-KEM-1024) |

For SSH, the tool identifies PQC KEX algorithms:

| Algorithm | Type |
|---|---|
| sntrup761x25519-sha512 | Hybrid (NTRU Prime + X25519) |
| mlkem768x25519-sha256 | Hybrid (ML-KEM-768 + X25519) |

For certificates, the tool recognizes ML-DSA (FIPS 204) and SLH-DSA (FIPS 205) signature algorithms. Servers presenting PQC certificates receive no certificate vulnerability finding, enabling them to reach LOW or INFO risk ratings.

---

# How It Works

The tool uses three components:

**Raw byte scanner** (`src/tls.rs`) — Constructs TLS ClientHello messages from scratch using `byteorder`, sends them over TCP, and parses the ServerHello response byte by byte. This is how the original pqcscan works. It tests each PQC group individually by offering it as the only supported group and checking if the server accepts or rejects it.

**rustls-based validator** (`src/handshake.rs`) — Uses the [rustls](https://github.com/rustls/rustls) TLS library with [rustls-post-quantum](https://crates.io/crates/rustls-post-quantum) to complete real handshakes with actual key exchange. This validates that the server doesn't just accept PQC groups but actually completes the full cryptographic handshake with them.

**Risk assessment engine** (`src/hndl.rs`) — Takes all collected data (PQC support, handshake results, TLS 1.2 fallback, certificate details, downgrade detection) and produces a severity-rated risk assessment.

---

# Contributing

The code is idiomatic Rust with zero warnings. Pull requests and issues are welcome.

The original pqcscan was created by Vincent Berg at [Anvil Secure](https://anvilsecure.com). This fork adds handshake validation, risk assessment, and related features.
