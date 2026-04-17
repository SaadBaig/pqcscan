# pqcscan - Post-Quantum Cryptography Scanner

*Scan SSH/TLS servers for PQC support*

> **Fork note:** This fork extends the original [pqcscan](https://github.com/anvilsecure/pqcscan) by Anvil Secure with full TLS handshake validation, negotiated behavior analysis, and downgrade attack detection.

# Overview

**pqcscan** is a small utility, written in Rust, that allows users to scan SSH and TLS servers for their stated support of Post-Quantum Cryptography algorithms. Scan results are written to JSON files. One or more of these result files can be converted into an easily digestible HTML report that can be viewed with a web browser. For sample screenshots look below in this README.

It might help system administrators and infosec practitioners with identifying those assets in their networks that do not support Post-Quantum Cryptography yet. The [USA](https://www.keyfactor.com/blog/nist-drops-new-deadline-for-pqc-transition/), [EU](https://digital-strategy.ec.europa.eu/en/library/recommendation-coordinated-implementation-roadmap-transition-post-quantum-cryptography) and [UK](https://www.ncsc.gov.uk/news/pqc-migration-roadmap-unveiled) have all set deadlines for phasing out non-PQC algorithms completely in between 2030-2035. A great overview about PQC for Engineers is being [drafted](https://www.ietf.org/archive/id/draft-ietf-pquip-pqc-engineers-12.html) by the IETF. It is our hope this initial version of pqcscan can help. Other scanners might, or already have, integrated such support too but having a dedicated tool focussed on one task might be more desirable at times.

To scan simply provide a list of hostnames/IPs and port numbers and chose the type of scan (SSH or TLS). Regarding the supported algorithms that can be identified:

- The list of SSH KEX (key exchange) PQC algorithms was manually put together based on [OpenSSH](https://www.openssh.com/), as well as [OQS-OpenSSH](https://github.com/open-quantum-safe/openssh). A lot of those algorithms are experimental algorithms and will hopefully never be encountered in production but they are useful for testing the tool and seeing if someone is deploying experimental algorithms in production in practice somewhere.
 
- For TLS the tool can identify all common and standardized PQC-hybrid and PQC algorithms. Experimental algorithms are right now not supported due to the increase in scanning time. These might be added in the future.

## What This Fork Adds

The original pqcscan reports what servers *advertise* — this fork goes further by validating what servers actually *negotiate and use*.

### Negotiated Behavior Validation
The raw-byte TLS scanner now fully parses the ServerHello response to extract:
- **Negotiated cipher suite** — the actual cipher the server selected
- **Negotiated key exchange group** — from the `key_share` extension
- **Negotiated TLS version** — from the `supported_versions` extension
- **HelloRetryRequest detection** — identifies when a server responds with an HRR (RFC 8446 sentinel random) rather than a full ServerHello

Protocol violations are logged as warnings: group mismatches (server picked a group you didn't offer), unexpected TLS versions, or cipher suites outside the offered set.

### Full Handshake Validation (`--validate-handshake`)
Using [rustls](https://github.com/rustls/rustls) with [rustls-post-quantum](https://crates.io/crates/rustls-post-quantum), the tool performs two complete TLS 1.3 handshakes per target:

1. **PQC-enabled handshake** — offers ML-KEM hybrid key exchange (X25519MLKEM768) alongside classical groups
2. **Classical-only handshake** — explicitly excludes all PQC/ML-KEM groups, offering only classical ECDH

Both handshakes complete the full key exchange, encrypted extensions, certificate verification, and Finished message exchange — not just the initial ClientHello/ServerHello.

### Downgrade Attack Detection
By comparing the results of both handshakes, the tool detects potential downgrade scenarios:
- **PQC offered and used** — server negotiated a PQC group when it was available
- **Classical fallback** — server gracefully falls back to classical groups when PQC is not offered
- **Potential downgrade warning** — server chose a classical group even though PQC was offered, which may indicate a misconfiguration, an intermediary stripping PQC support, or a deliberate downgrade

### New Dependencies
This fork adds the following crates:
- `rustls` (with `prefer-post-quantum` and `aws_lc_rs` features)
- `rustls-post-quantum` — provides the PQC-enabled crypto provider
- `webpki-roots` — Mozilla root certificate store
 
## Bugs, comments, suggestions
The code should be somewhat idiomatic Rust, but there will be tons of ways to improve it. From the way the HTML files are now built up and generated to other smaller issues. For more information see the `TODO` file in the repository. All input is welcome! Just send in direct pull requests or bugs/issues via GitHub. You are also welcome to directly email the principal author and maintainer, Vincent Berg, at *gvb@anvilsecure.com*.
 
# Installation

## Binary Releases
There are binary releases for Linux, MacOS and Windows on common architectures on the [releases](https://github.com/anvilsecure/pqcscan/releases) page. Download the files, unzip to your desired location, and run the extracted binary from your shell.

## Building from source
The implementation is straight forward Rust. You can download a tagged version's source distribution from the [releases](https://github.com/anvilsecure/pqcscan/releases) page. Or simply clone the git repository and then run:

```
git clone https://github.com/anvilsecure/pqcscan.git
cd pqcscan
cargo build --release
./target/release/pqcscan --help
```

# Usage

To TLS scan two hosts and combine it in one report do something like the following:

```
pqcscan tls-scan -t gmail.com:443 -o gmail.json
pqcscan tls-scan -t pq.cloudflareresearch.com:443 -o cloudflare.json
pqcscan create-report -i gmail.json cloudflare.json -o report.html
```

## Full Handshake Validation

To perform full TLS handshake validation with downgrade detection, add the `--validate-handshake` flag:

```
pqcscan tls-scan -t cloudflare.com:443 --validate-handshake -o cloudflare.json
pqcscan create-report -i cloudflare.json -o report.html
```

This performs two real TLS 1.3 handshakes per target (PQC-enabled and classical-only), extracts the negotiated parameters from each, and compares them to flag potential downgrade issues. The results appear in both the JSON output and the HTML report.

Example output:

```
$ pqcscan tls-scan -t cloudflare.com:443 --validate-handshake

═══════════════════════════════════════════════════════════════
  PQCscan Summary
═══════════════════════════════════════════════════════════════

  Scanned 1 target(s) in 0.47s

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
  │    Server negotiated PQC group (X25519MLKEM768) when offered.
  │    Classical fallback also works (X25519).
  └────────────────────────────────────────

═══════════════════════════════════════════════════════════════
```

## Standard Usage

You can also create a target list in a file and supply it via `-T`. This works for both `tls-scan` and `ssh-scan`.

```
echo github.com > targets
echo 100.126.128.144 >> targets
pqcscan ssh-scan -T targets -o ssh.json
pqcscan create-report -i ssh.json -o report.html
```

To get more feedback what is going on just the Rust [loglevels](https://docs.rs/env_logger/latest/env_logger/).

```
RUST_LOG=debug pqcscan ssh-scan -T targets -o ssh.json
[2025-06-20T07:49:35Z DEBUG pqcscan::ssh] Started SSH scanning github.com:22
[2025-06-20T07:49:35Z DEBUG pqcscan::ssh] Started SSH scanning 100.126.128.144:22
[2025-06-20T07:49:35Z DEBUG pqcscan::ssh] PQC Algorithm supported: sntrup761x25519-sha512
[2025-06-20T07:49:35Z DEBUG pqcscan::ssh] PQC Algorithm supported: sntrup761x25519-sha512@openssh.com
[2025-06-20T07:49:35Z DEBUG pqcscan::ssh] Non-PQC Algorithm supported: curve25519-sha256
[2025-06-20T07:49:35Z DEBUG pqcscan::ssh] Non-PQC Algorithm supported: curve25519-sha256@libssh.org
...
[2025-06-20T07:49:35Z INFO  pqcscan::scan] Done scanning. All threads exited.
```

For configuring the number of scan threads and other options just use `--help`. 


# Screenshots

## Main Scan Results Overview

![Example Scan Results Main Overview](/doc/pqcscan_results_sample1.png)

## SSH Scan Results Sample

![SSH Scan Results Sample](/doc/sshscan_results_sample1.png)

## TLS Scan Results Sample

![TLS Scan Results Sample](/doc/tlsscan_results_sample1.png)
