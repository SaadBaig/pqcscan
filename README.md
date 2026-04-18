# pqcscan - Post-Quantum Cryptography Scanner

*Scan SSH/TLS servers for PQC support, validate real handshake behavior, and assess quantum risk*

> **Fork note:** This fork extends [pqcscan](https://github.com/anvilsecure/pqcscan) by Anvil Secure with full TLS handshake validation, downgrade attack detection, HNDL risk assessment, SCSV fallback testing, and X.509 certificate analysis. It goes beyond checking what servers advertise to validating what they actually negotiate — and flags whether captured traffic is decryptable by a future quantum computer. Stick around till the end for a crash course on Rust's core security innovation and why it matters for security tooling.

---

# Why This Matters

The timeline for quantum computers breaking cryptography just got shorter. In April 2026, two independent breakthroughs changed the calculus:

- **Google announced** a dramatically improved quantum algorithm for breaking elliptic curve cryptography (P-256), backed by a zero-knowledge proof. They did not publish the algorithm itself.
- **Oratomic published** resource estimates showing that breaking RSA-2048 and P-256 on a neutral atom quantum computer requires only ~10,000 qubits — far fewer than previous estimates of millions.

These advances compound: neutral atom architectures turned out to be more scalable than expected, their qubit connectivity enables far more efficient error-correcting codes (3-4 physical qubits per logical qubit vs ~1,000 for superconducting), and the algorithms to crack cryptography now require less work. The result is that Q-Day — the day quantum computers can break deployed cryptography — has been [pulled forward significantly](https://blog.cloudflare.com/post-quantum-roadmap/) from typical 2035+ timelines. Google has accelerated their migration target to 2029. IBM Quantum Safe's CTO [can't rule out](https://blog.cloudflare.com/post-quantum-roadmap/) quantum attacks on high-value targets as early as 2029.

### Two categories of threat

**Harvest Now, Decrypt Later (HNDL)** — Adversaries record encrypted traffic today and store it until quantum computers can decrypt it. Any data with a long shelf life (medical records, financial data, state secrets, intellectual property) is already at risk. This is the threat that post-quantum *encryption* (key exchange) addresses, and it's been the industry's primary focus since Cloudflare enabled PQ encryption by default in 2022. Over 65% of human traffic to Cloudflare is now post-quantum encrypted.

**Quantum-forged authentication** — Once quantum computers arrive, an attacker can forge certificates, sign malicious code updates, and impersonate servers in real time. As [Cloudflare notes](https://blog.cloudflare.com/post-quantum-roadmap/): "data leaks are severe, but broken authentication is catastrophic. Any overlooked quantum-vulnerable remote-login key is an access point for an attacker to do as they wish." This is the next frontier — post-quantum *signatures* (ML-DSA, SLH-DSA) — and no production TLS servers use PQC certificates yet.

### The downgrade problem

Adding PQC support is necessary but not sufficient. Servers must also *disable* quantum-vulnerable cryptography to prevent downgrade attacks. Our scan of 457 top domains found that **99.6% still accept TLS 1.2** — meaning an active attacker can force any connection back to a quantum-vulnerable protocol, even if the server supports PQC on TLS 1.3. As long as the legacy path exists, the HNDL risk remains.

The [USA](https://www.keyfactor.com/blog/nist-drops-new-deadline-for-pqc-transition/), [EU](https://digital-strategy.ec.europa.eu/en/library/recommendation-coordinated-implementation-roadmap-transition-post-quantum-cryptography), and [UK](https://www.ncsc.gov.uk/news/pqc-migration-roadmap-unveiled) have set deadlines for phasing out non-PQC algorithms between 2030-2035. NIST standardized the first post-quantum algorithms in August 2024: [ML-KEM](https://csrc.nist.gov/pubs/fips/203/final) (FIPS 203) for key exchange, [ML-DSA](https://csrc.nist.gov/pubs/fips/204/final) (FIPS 204) and [SLH-DSA](https://csrc.nist.gov/pubs/fips/205/final) (FIPS 205) for signatures.

This tool answers a simple question: **is your infrastructure ready?**

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
Compares handshake results to detect **downgrade attacks** (server chose classical when PQC was offered) and runs a **Harvest Now, Decrypt Later** risk assessment with eight heuristic checks:

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

X.509 certificates are parsed to extract key type (RSA, ECDSA-P-256, Ed25519), key size, and validity period. SSH servers get their own HNDL assessment based on advertised KEX algorithms and classical fallback risk.

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

# Real-World Findings

Tested against 457 of the internet's top domains (April 2026):

| Metric | Result |
|---|---|
| PQC key exchange supported | **53%** (242 of 449 successful scans) |
| TLS 1.2 fallback accepted | **99.6%** (447 of 449) |
| HNDL CRITICAL | 207 servers |
| HNDL HIGH | 242 servers |
| HNDL MEDIUM or lower | **0 servers** |
| SCSV fallback supported | 283 (63%) |
| RSA certificates | 220 (49%) |
| ECDSA certificates | 166 (37%) |
| Long-lived certs (>1 year) | 96 (21%) |

### Key takeaways

**The good news:** Over half the internet's top sites now support PQC key exchange, primarily X25519MLKEM768. Google leads with standalone ML-KEM-1024 support. Cloudflare, Apple, Meta, Wikipedia, Reddit, Discord, and OpenAI all negotiate PQC when offered.

**The bad news:** Not a single server scored below HIGH on the HNDL assessment. The reason: 99.6% still accept TLS 1.2 fallback. Even servers with perfect PQC on TLS 1.3 remain vulnerable to downgrade attacks that force connections back to quantum-breakable key exchange. As [Cloudflare's PQ roadmap](https://blog.cloudflare.com/post-quantum-roadmap/) emphasizes, "adding support for PQ cryptography is not enough — systems must disable support for quantum-vulnerable cryptography to be secure against downgrade attacks."

**Financial institutions are behind:** Chase, Wells Fargo, Barclays, Capital One, Citibank, and Morgan Stanley — all CRITICAL. No PQC, RSA-2048 certificates, and in several cases no SCSV fallback protection. These are exactly the "high-value targets" that Cloudflare warns will be prioritized by early quantum attackers: "long-lived keys that unlock substantial assets or persistent access."

**The authentication gap is real:** 49% of servers still use RSA certificates and 21% have certificate validity periods over one year. These are the long-lived quantum-vulnerable keys that Cloudflare identifies as the highest priority to upgrade. Once a quantum computer can forge an RSA-2048 signature — which Oratomic estimates requires only ~10,000 neutral atom qubits — every one of these certificates becomes an attack vector. No production server uses PQC certificates (ML-DSA) yet.

**Security vendors aren't practicing what they preach:** Zscaler and Tenable, both of which sell quantum-readiness assessments, don't support PQC on their own websites. Both have long-lived RSA-2048 certificates.

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
pqcscan tls-scan -t cloudflare.com:443

# Scan a single SSH target
pqcscan ssh-scan -t github.com:22

# Scan from a target list
pqcscan tls-scan -T targets.txt -o results.json

# Generate an HTML report
pqcscan create-report -i results.json -o report.html
```

## Full Handshake Validation with HNDL Assessment

```bash
pqcscan tls-scan -t cloudflare.com:443 --validate-handshake
```

This performs three real handshakes, tests SCSV fallback signaling, parses the server certificate, and produces an HNDL risk rating.

## CSV Export

```bash
pqcscan tls-scan -T targets.txt --validate-handshake --csv results.csv
```

One row per target with columns: host, port, protocol, pqc_supported, pqc_algorithms, negotiated_group, negotiated_cipher, tls12_fallback, hndl_risk, scsv_supported, cert_key_type, cert_key_bits, cert_validity_days.

## Example Output

```
$ pqcscan tls-scan -t cloudflare.com:443 --validate-handshake

═══════════════════════════════════════════════════════════════
  PQCscan Summary
═══════════════════════════════════════════════════════════════

  Scanned 1 target(s) in 0.57s

  ┌─ cloudflare.com:443 (TLS)
  │  PQC Support:    ✅ Yes
  │  PQC Algorithms: X25519MLKEM768
  │
  │  Full Handshake (PQC-enabled):
  │    Status:       ✅ Completed
  │    Cipher Suite: TLS13_AES_256_GCM_SHA384
  │    Key Exchange: X25519MLKEM768
  │    TLS Version:  TLSv1_3
  │
  │  Full Handshake (Classical-only):
  │    Status:       ✅ Completed
  │    Key Exchange: X25519
  │
  │  Downgrade Assessment:
  │    ✅ PQC negotiated when offered
  │    ✅ Classical fallback available
  │
  │  HNDL Risk:      🟠 HIGH
  │  ⚠️  Traffic captured today is decryptable post-quantum
  │
  │    ℹ️  PQC Key Exchange Active
  │      Server negotiates PQC key exchange (X25519MLKEM768) —
  │      TLS 1.3 sessions are quantum-resistant.
  │
  │    🟠 TLS 1.2 Fallback Available
  │      Server accepts TLS 1.2 fallback. Classical DH/ECDH key
  │      exchange is quantum-vulnerable. An attacker can downgrade
  │      connections to TLS 1.2 and harvest traffic.
  │
  │    🟡 ECDSA Certificate
  │      Server uses ECDSA-P-256 certificate. ECDSA is
  │      quantum-vulnerable. Certificate authentication can be
  │      forged post-quantum.
  │
  │    ℹ️  Short-Lived Certificate
  │      Certificate validity period is 90 days.
  └────────────────────────────────────────

═══════════════════════════════════════════════════════════════
```

## Verbose Logging

```bash
RUST_LOG=debug pqcscan tls-scan -t example.com:443 --validate-handshake
```

## All Options

```
pqcscan tls-scan --help
pqcscan ssh-scan --help
pqcscan create-report --help
```

Key flags for `tls-scan`:
- `-t HOST:PORT` — single target
- `-T FILE` — target list (one per line, `#` comments supported)
- `-o FILE` — JSON output
- `--csv FILE` — CSV output
- `--validate-handshake` — full handshake validation + HNDL assessment
- `--only-hybrid-algos` — limit to hybrid PQC algorithms
- `--test-nonpqc-algos` — also test classical groups
- `--num-threads N` — parallel scan threads (default: 8)

---

# How It Works

The tool uses two complementary approaches:

**Raw byte scanner** (`src/tls.rs`) — Constructs TLS ClientHello messages from scratch using `byteorder`, sends them over TCP, and parses the ServerHello response byte by byte. This is how the original pqcscan works. It tests each PQC group individually by offering it as the only supported group and checking if the server accepts or rejects it.

**rustls-based validator** (`src/handshake.rs`) — Uses the [rustls](https://github.com/rustls/rustls) TLS library with [rustls-post-quantum](https://crates.io/crates/rustls-post-quantum) to complete real handshakes with actual key exchange. This validates that the server doesn't just accept PQC groups but actually completes the full cryptographic handshake with them.

**HNDL engine** (`src/hndl.rs`) — Takes all collected data (PQC support, handshake results, TLS 1.2 fallback, certificate details, downgrade detection) and produces a severity-rated risk assessment.

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
let (pqc, classical, tls12, downgrade) =
    handshake::validate_handshake(config, target);

let hndl_input = hndl::HndlInput {
    handshake_pqc: Some(&pqc),
    handshake_classical: Some(&classical),
    // ...
};
let assessment = hndl::assess_hndl_risk(&hndl_input);
```

`&pqc` borrows `pqc`. The compiler checks that `pqc` lives longer than `hndl_input`. Since both are local variables in the same block, this is fine. If you tried to return `hndl_input` from this function while `pqc` was dropped, the compiler would catch it.

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
