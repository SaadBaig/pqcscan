<p align="center">
  <img src="images/pqcscan.jpg" alt="...">
</p>


*Scan SSH/TLS servers for PQC support, validate real handshake behavior, and assess quantum risk*

> **Fork note:** This fork extends [pqcscan](https://github.com/anvilsecure/pqcscan) by Anvil Secure with full TLS handshake validation, downgrade attack detection, quantum risk assessment, SCSV fallback testing, and X.509 certificate analysis. It goes beyond checking what servers advertise to validating what they actually negotiate — and flags whether captured traffic is decryptable by a future quantum computer. Stick around till the end for a crash course on Rust's core security innovation and why it matters for security tooling.

## Table of Contents

- [What pqcscan Does](#what-pqcscan-does)
  - [Level 1: Advertisement Detection](#level-1-advertisement-detection-default)
  - [Level 2: Full Handshake Validation](#level-2-full-handshake-validation---validate-handshake)
  - [Level 3: Risk Assessment](#level-3-risk-assessment)
- [Validated PQC Algorithms](#validated-pqc-algorithms)
- [Installation](#installation)
- [Usage](#usage)
  - [Quick Scan](#quick-scan-advertisement-detection)
  - [Full Handshake Validation with Risk Assessment](#full-handshake-validation-with-risk-assessment)
  - [CSV Export](#csv-export)
  - [HTML Report](#html-report)
  - [Example Output](#example-output)
  - [All Options](#all-options)
- [How It Works](#how-it-works)
- [Screenshots](#screenshots)
- [Contributing](#contributing)
- [A Crash Course on Rust's Core Security Innovation](#a-crash-course-on-rusts-core-security-innovation)

---
---

# What pqcscan Does

**pqcscan** scans SSH and TLS servers for post-quantum cryptography support. It operates at three levels of depth:

### Level 1: Advertisement Detection (default)
Sends raw TLS ClientHello messages to probe which PQC key exchange groups a server accepts. Parses the ServerHello to extract the negotiated cipher suite, key exchange group, TLS version, and detects HelloRetryRequests (RFC 8446). For SSH, reads the server's `SSH_MSG_KEXINIT` to identify PQC KEX algorithms.

### Level 2: Full Handshake Validation (`--validate-handshake`)
Completes three real TLS handshakes per target using [rustls](https://github.com/rustls/rustls):

1. **PQC-enabled** (TLS 1.3) — offers ML-KEM hybrid key exchange alongside classical groups
2. **Classical-only** (TLS 1.3) — excludes all PQC groups to test fallback behavior
3. **TLS 1.2 probe** — tests whether the server accepts the legacy protocol

Each handshake goes through the full lifecycle: key exchange, encrypted extensions, certificate verification, and Finished messages. The tool also tests [TLS_FALLBACK_SCSV](https://www.rfc-editor.org/rfc/rfc7507) (RFC 7507) to check if the server detects version downgrade attempts.

### Level 3: Risk Assessment
Compares handshake results to detect **downgrade attacks** (server chose classical when PQC was offered) and runs a quantum risk assessment with eight heuristic checks:

| Check | What it detects | Severity |
|---|---|---|
| No PQC key exchange | All traffic is quantum-decryptable | 🔴 CRITICAL |
| Static RSA key exchange | TLS 1.2 with no forward secrecy | 🔴 CRITICAL |
| TLS 1.2 fallback | Attacker can downgrade to quantum-vulnerable protocol | 🟠 HIGH |
| PQC advertised but not negotiated | Server claims PQC but chose classical | 🟠 HIGH |
| Downgrade amplification | Active attacker can force quantum-vulnerable exchange | 🟠 HIGH |
| Weak classical groups | secp256r1/X25519 offer less quantum margin | 🟡 MEDIUM |
| Long-lived certificates | Extended impersonation window | 🟡 MEDIUM |
| RSA/ECDSA certificates | Classical keys are quantum-forgeable | 🟡 MEDIUM |

X.509 certificates are parsed to extract key type (RSA, ECDSA-P-256, Ed25519), key size, and validity period. SSH servers get their own risk assessment based on advertised KEX algorithms and classical fallback risk.

---

# Validated PQC Algorithms

The tool covers all NIST FIPS 203 (ML-KEM) key exchange variants deployed in TLS today:

| Algorithm | Type | TLS Group ID |
|---|---|---|
| ML-KEM-512 | Standalone | 0x0200 (512) |
| ML-KEM-768 | Standalone | 0x0201 (513) |
| ML-KEM-1024 | Standalone | 0x0202 (514) |
| X25519MLKEM768 | Hybrid (X25519 + ML-KEM-768) | 0x11EC (4588) |
| SECP256R1MLKEM768 | Hybrid (P-256 + ML-KEM-768) | 0x11EB (4587) |
| SECP384R1MLKEM1024 | Hybrid (P-384 + ML-KEM-1024) | 0x11ED (4589) |

For SSH, the tool identifies PQC KEX algorithms including `sntrup761x25519-sha512` (OpenSSH) and `mlkem768x25519-sha256` (newer implementations).

ML-DSA (FIPS 204) and SLH-DSA (FIPS 205) signature algorithms are not yet covered — no production TLS servers use PQC certificates today.

---
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
pqcscan ssh-scan -t github.com:22

# Scan from a target list with JSON output
pqcscan tls-scan -T targets.txt -o results.json

# Scan with HTML report
pqcscan tls-scan -T targets.txt --validate-handshake --report report.html

# Convert JSON results to HTML report
pqcscan create-report -i results.json -o report.html
```

## Full Handshake Validation with Risk Assessment

```bash
pqcscan tls-scan -t cloudflare.com --validate-handshake
```

This performs three real handshakes, tests SCSV fallback signaling, parses the server certificate, and produces a risk rating.

## CSV Export

```bash
pqcscan tls-scan -T targets.txt --validate-handshake --csv results.csv
```

One row per target with columns: host, port, protocol, pqc_supported, pqc_algorithms, negotiated_group, negotiated_cipher, tls12_fallback, risk_level, scsv_supported, cert_key_type, cert_key_bits, cert_validity_days.

## HTML Report

```bash
# Generate directly from a scan
pqcscan tls-scan -T targets.txt --validate-handshake --report report.html

# Or convert existing JSON results
pqcscan create-report -i results.json -o report.html
```

The `--report` flag works on both `tls-scan` and `ssh-scan` subcommands, generating an HTML report directly from scan results without needing an intermediate JSON file.

## Example Output

```
$ pqcscan tls-scan -t cloudflare.com --validate-handshake

═══════════════════════════════════════════════════════════════
  PQCscan Summary
═══════════════════════════════════════════════════════════════

  Scanned cloudflare.com:443 in 5.05s

  ┌─ cloudflare.com:443 (TLS)
  │  ✅ PQC Support:   Yes (X25519MLKEM768)
  │
  │  ── Handshake Validation ──
  │  ✅ PQC-only:     X25519MLKEM768 (TLS 1.3)
  │  ✅ TLS Fallback SCSV: Supported
  │
  │  ── Risk Assessment (🟠 HIGH) ──
  │  ✅ PQC active on TLS 1.3 — sessions quantum-resistant
  │  ⚠️  Vulnerable key exchange algorithms: ECDHE (TLS 1.2), X25519 (TLS 1.3)
  │  ⚠️  Vulnerable certificate algorithms:  ECDSA-P-256
  │
  │  ── Remediation ──
  │  🔧 Plan TLS 1.2 deprecation per NIST SP 800-52 Rev. 2 (target: 2030)
  │  🔧 Adopt ML-DSA certificates when available for quantum-safe authentication
  └────────────────────────────────────────

═══════════════════════════════════════════════════════════════
```

## Verbose Logging

```bash
RUST_LOG=debug pqcscan tls-scan -t example.com --validate-handshake
```

## All Options

```
pqcscan tls-scan --help
pqcscan ssh-scan --help
pqcscan create-report --help
```

Key flags for `tls-scan`:
- `-t HOST:PORT` — single target (port 443 is default)
- `-T FILE` — target list (one per line, `#` comments supported)
- `-o FILE` — JSON output
- `--csv FILE` — CSV output
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

---

# How It Works

The tool uses two complementary approaches:

**Raw byte scanner** (`src/tls.rs`) — Constructs TLS ClientHello messages from scratch using `byteorder`, sends them over TCP, and parses the ServerHello response byte by byte. This is how the original pqcscan works. It tests each PQC group individually by offering it as the only supported group and checking if the server accepts or rejects it.

**rustls-based validator** (`src/handshake.rs`) — Uses the [rustls](https://github.com/rustls/rustls) TLS library with [rustls-post-quantum](https://crates.io/crates/rustls-post-quantum) to complete real handshakes with actual key exchange. This validates that the server doesn't just accept PQC groups but actually completes the full cryptographic handshake with them.

**Risk assessment engine** (`src/hndl.rs`) — Takes all collected data (PQC support, handshake results, TLS 1.2 fallback, certificate details, downgrade detection) and produces a severity-rated risk assessment.

---

# Screenshots

## Main Scan Results Overview

![Example Scan Results Main Overview](/doc/pqcscan_results_sample1.png)

## SSH Scan Results Sample

![SSH Scan Results Sample](/doc/sshscan_results_sample1.png)

## TLS Scan Results Sample

![TLS Scan Results Sample](/doc/tlsscan_results_sample1.png)

---

# Contributing

The code is idiomatic Rust with zero warnings. Pull requests and issues are welcome. See the `TODO` file for known areas of improvement.

The original pqcscan was created by Vincent Berg at [Anvil Secure](https://anvilsecure.com). This fork adds handshake validation, HNDL assessment, and related features.


---

# A Crash Course on Rust's Core Security Innovation

This project is written in Rust. If you're new to the language, here's why that matters — especially for a security tool that parses untrusted network data.

## The Problem Ownership Solves

In C/C++, memory bugs are the #1 source of security vulnerabilities — use-after-free, double-free, buffer overflows, data races. These happen because the programmer manually manages memory and the compiler has no way to verify you did it correctly. In languages like Python or Go, a garbage collector handles it for you, but at a runtime performance cost and with less predictability.

Rust's insight: what if the compiler could verify memory safety at compile time, with zero runtime cost? That's ownership.

## The Three Rules

Rust's entire memory model comes down to three rules enforced by the compiler:

1. Every value has exactly one owner
2. When the owner goes out of scope, the value is dropped (freed)
3. You can either have one mutable reference OR any number of immutable references — never both at the same time

Here's how they show up in this codebase.

### Rule 1: One Owner

Look at `scan_runner` in `scan.rs`:

```rust
for target in scan.targets {
    tx.send(target).await;
}
```

When you iterate with `for target in scan.targets`, each target is *moved* out of the vector. After this loop, `scan.targets` is empty — you can't use it again. The target value was moved into `tx.send()`, which now owns it. If you tried to use `scan.targets` after this loop, the compiler would refuse to compile.

This is different from every other language you may have used. In Python, `for target in targets` gives you a reference — the list still has the items. In Rust, the items are gone.

### Rule 2: Drop When Out of Scope

In `do_handshake` in `handshake.rs`:

```rust
let mut tcp = match TcpStream::connect_timeout(...) {
    Ok(s) => s,
    Err(e) => { return HandshakeValidation { ... }; }
};
// ... use tcp ...
// When this function returns, tcp is dropped automatically
```

When `tcp` goes out of scope (the function returns), Rust automatically closes the TCP socket. No `defer`, no `finally`, no try-with-resources. The compiler inserts the cleanup code for you. This is called RAII (Resource Acquisition Is Initialization) — same concept as C++ destructors, but the compiler guarantees you can't use the value after it's freed.

This is why you never see `close()` calls in the codebase. Every socket, every file handle, every allocation is cleaned up automatically when its owner goes out of scope.

### Rule 3: Borrowing

This is where it gets interesting. Look at `check_pqc_key_exchange` in `hndl.rs`:

```rust
fn check_pqc_key_exchange(input: &HndlInput, findings: &mut Vec<HndlFinding>) {
```

Two different kinds of borrows here:

- `&HndlInput` — an immutable (shared) reference. The function can read `input` but can't modify it. Multiple functions could hold `&HndlInput` simultaneously.
- `&mut Vec<HndlFinding>` — a mutable (exclusive) reference. The function can push new findings into the vector. But while this function holds `&mut`, nothing else can access `findings` at all.

Why? Imagine two threads both holding `&mut Vec`. Thread A pushes an element, which triggers a reallocation (the vector grows). Thread B is iterating over the vector. Thread B is now reading freed memory. Use-after-free. Data race. In C, this compiles fine and crashes at runtime. In Rust, the compiler rejects it.

## How This Shows Up in This Codebase

### `Arc` — Shared ownership across threads

In `scan.rs`:

```rust
pub async fn scan_runner(config: Arc<Config>, scan: ScanOptions) -> Scan {
    // ...
    let config = config.clone();
    tokio::spawn(async move {
        // each thread has its own Arc pointing to the same Config
    });
}
```

Normally, a value has one owner. But scan threads all need to read the config. `Arc` (Atomic Reference Count) lets multiple owners share the same data. Each `.clone()` increments a counter. When the last `Arc` is dropped, the data is freed. The key constraint: `Arc` only gives you `&Config` (immutable). You can't mutate shared data — that would be a data race.

### `clone()` — Explicit copying

In `tls.rs`:

```rust
pqc_algos.push(group_name.clone());
```

`group_name` is a `String`. If you wrote `pqc_algos.push(group_name)`, the string would be *moved* into the vector, and you couldn't use `group_name` on the next loop iteration. `.clone()` makes an explicit copy. Rust forces you to be intentional about copies — in Python, you'd never notice the copy happening.

### Lifetimes — How long borrows last

In `hndl.rs`:

```rust
pub struct HndlInput<'a> {
    pub pqc_supported: bool,
    pub handshake_pqc: Option<&'a HandshakeValidation>,
    pub handshake_classical: Option<&'a HandshakeValidation>,
    // ...
}
```

The `'a` is a lifetime parameter. It says: "this struct contains references to `HandshakeValidation` values, and those values must live at least as long as this struct does." The compiler verifies this. If you tried to create an `HndlInput` that outlives the `HandshakeValidation` it points to, the compiler would reject it.

Look at how it's used in `tls.rs`:

```rust
let hs_result = handshake::validate_handshake(config, target);

let hndl_input = hndl::HndlInput {
    handshake_pqc: Some(&hs_result.pqc),
    handshake_classical: Some(&hs_result.classical),
    // ...
};
let assessment = hndl::assess_hndl_risk(&hndl_input);
```

`&hs_result.pqc` borrows `hs_result.pqc`. The compiler checks that `hs_result` lives longer than `hndl_input`. Since both are local variables in the same block, this is fine. If you tried to return `hndl_input` from this function while `hs_result` was dropped, the compiler would catch it.

## Why This Matters for a Security Tool

This tool connects to untrusted servers and parses their responses. In C, a malformed ServerHello could cause a buffer overflow in your parser. In Rust:

```rust
let mut buf: [u8; 16384] = [0; 16384];
let read = stream.read(&mut buf)?;
let mut cursor = Cursor::new(buf);
let content_type = cursor.read_u8()?;
```

- The buffer is stack-allocated with a fixed size — no heap overflow possible
- `Cursor` tracks its position and returns errors if you read past the end — no out-of-bounds read
- Every `?` handles the error case — no unchecked return values

The compiler guarantees your TLS parser can't have memory corruption bugs. For a tool that's probing potentially hostile servers, that's not just nice to have — it's essential.

## The Trade-off

The cost is the learning curve. The compiler is strict. It rejects code that would be fine in other languages because it can't *prove* it's safe. Sometimes you have to restructure code to satisfy the borrow checker. But once it compiles, an entire class of bugs is eliminated — not by testing, not by code review, but by mathematical proof at compile time.

That's why Rust is used for security-critical infrastructure: Firefox's rendering engine, the Linux kernel, Cloudflare's edge network, and tools like this one that parse untrusted network data.
