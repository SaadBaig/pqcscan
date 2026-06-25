use anyhow::{anyhow, Result};
use chrono::prelude::*;
use clap::{crate_version, Arg, ArgAction, ArgMatches, Command};
use env_logger::Env;
use rust_embed::RustEmbed;
use std::fs::File;
use std::io::{BufRead, BufReader, BufWriter};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::runtime::Runtime;

mod config;
mod handshake;
mod hndl;
mod scan;
mod ssh;
mod tls;
mod tlsconstants;
mod utils;
#[cfg(test)]
mod tests;

use crate::config::Config;
use crate::scan::{scan_runner, Scan, ScanOptions, ScanResult, ScanType};
use crate::utils::{parse_single_target, Target};

fn print_scan_summary(results: &Scan) {
    println!();
    println!("═══════════════════════════════════════════════════════════════");
    println!("  PQCscan Summary");
    println!("═══════════════════════════════════════════════════════════════");
    println!();

    let duration = (results.end_time - results.start_time).num_milliseconds() as f64 / 1000.0;
    if results.results.len() == 1 {
        // Single target — show the domain name
        let target_name = match &results.results[0] {
            ScanResult::Tls { targetspec, .. } => format!("{}", targetspec),
            ScanResult::Ssh { targetspec, .. } => format!("{}", targetspec),
            _ => "1 target".to_string(),
        };
        println!("  Scanned {} in {:.2}s", target_name, duration);
    } else {
        println!("  Scanned {} target(s) in {:.2}s", results.results.len(), duration);
    }
    println!();

    for result in &results.results {
        match result {
            ScanResult::Tls {
                targetspec,
                error,
                pqc_supported,
                pqc_algos,
                hybrid_algos,
                handshake_pqc,
                handshake_classical,
                handshake_tls12,
                hndl_assessment,
                scsv_supported,
                ..
            } => {
                println!("  ┌─ {} (TLS)", targetspec);

                if let Some(err) = error {
                    println!("  │  Error: {}", err);
                    println!("  └────────────────────────────────────────");
                    println!();
                    continue;
                }

                // Only show PQC Support headline in quick-scan mode (no handshake validation)
                if handshake_pqc.is_none() && handshake_tls12.is_none() {
                    let mut algos = Vec::new();
                    if let Some(pqc) = pqc_algos { algos.extend(pqc.iter().cloned()); }
                    if let Some(hybrid) = hybrid_algos { algos.extend(hybrid.iter().cloned()); }
                    algos.sort();

                    if *pqc_supported {
                        println!("  │  ✅ PQC Support:   Yes ({})", algos.join(", "));
                    } else {
                        println!("  │  ❌ PQC Support:   No");
                    }
                }

                // Combined Assessment section (only shown when --validate-handshake is used)
                if let Some(hndl) = hndl_assessment {
                    let risk_icon = match hndl.risk_level {
                        crate::hndl::HndlSeverity::Critical => "🔴",
                        crate::hndl::HndlSeverity::High => "🟠",
                        crate::hndl::HndlSeverity::Medium => "🟡",
                        crate::hndl::HndlSeverity::Low => "🟢",
                        crate::hndl::HndlSeverity::Info => "✅",
                    };
                    println!("  │");
                    println!("  │  {} Risk Assessment: {}", risk_icon, hndl.risk_level);

                    // PQC Key Exchange result
                    if let Some(pqc_hs) = handshake_pqc {
                        if pqc_hs.completed {
                            let group = pqc_hs.negotiated_group.as_deref().unwrap_or("-");
                            println!("  │  ✅ PQC Key Exchange: {} (TLS 1.3)", group);
                        } else {
                            println!("  │  ❌ PQC Key Exchange: Failed");
                        }
                    }

                    // SCSV
                    if let Some(scsv) = scsv_supported {
                        if *scsv {
                            println!("  │  ✅ TLS Fallback SCSV: Supported");
                        } else {
                            println!("  │  ❌ TLS Fallback SCSV: Not supported");
                        }
                    }

                    // Findings
                    for finding in &hndl.findings {
                        match finding.category.as_str() {
                            "PQC Key Exchange Active" => continue, // already shown above
                            "No PQC Key Exchange" => continue, // already shown via ❌ PQC Key Exchange: Failed
                            "TLS 1.2 Fallback Available" => {
                                let group = handshake_classical.as_ref()
                                    .and_then(|h| h.negotiated_group.as_deref())
                                    .unwrap_or("X25519");
                                println!("  │  ⚠️  Vulnerable key exchange algorithms:");
                                println!("  │        - ECDHE (TLS 1.2)");
                                println!("  │        - {} (TLS 1.3)", group);
                            }
                            "TLS 1.2 Static RSA Key Exchange" => {
                                println!("  │  ⚠️  Vulnerable key exchange algorithms:");
                                println!("  │        - static RSA (TLS 1.2) — no forward secrecy");
                            }
                            "TLS 1.2 Not Supported" => continue,
                            "Standard Classical Key Exchange" | "Strong Classical Key Exchange" | "Finite Field DH Key Exchange" => continue,
                            "PQC Advertised But Not Negotiated" => {
                                println!("  │  ⚠️  PQC advertised but classical chosen in practice");
                            }
                            "Deprecated PQC Algorithm" => {
                                let group = handshake_pqc.as_ref()
                                    .and_then(|h| h.negotiated_group.as_deref())
                                    .unwrap_or("Kyber draft");
                                println!("  │  ⚠️  Deprecated PQC algorithm:");
                                println!("  │        - {} (migrate to ML-KEM)", group);
                            }
                            "Downgrade Amplifies Risk" => {
                                println!("  │  ⚠️  Downgrade possible — attacker can force classical");
                            }
                            "RSA-2048 Certificate" => {
                                println!("  │  ⚠️  Vulnerable certificate algorithms:");
                                println!("  │        - RSA-2048");
                            }
                            "RSA Certificate" => {
                                println!("  │  ⚠️  Vulnerable certificate algorithms:");
                                println!("  │        - RSA");
                            }
                            "ECDSA Certificate" => {
                                let hs = handshake_pqc.as_ref()
                                    .filter(|h| h.completed)
                                    .or(handshake_classical.as_ref().filter(|h| h.completed))
                                    .or(handshake_tls12.as_ref().filter(|h| h.completed));
                                let kt = hs.and_then(|h| h.peer_certificate_key_type.as_deref())
                                    .unwrap_or("ECDSA");
                                println!("  │  ⚠️  Vulnerable certificate algorithms:");
                                println!("  │        - {}", kt);
                            }
                            "PQC Certificate" => {
                                let hs = handshake_pqc.as_ref()
                                    .filter(|h| h.completed)
                                    .or(handshake_classical.as_ref().filter(|h| h.completed))
                                    .or(handshake_tls12.as_ref().filter(|h| h.completed));
                                let kt = hs.and_then(|h| h.peer_certificate_key_type.as_deref())
                                    .unwrap_or("ML-DSA");
                                println!("  │  ✅ PQC Certificate: {}", kt);
                            }
                            "Long-Lived Certificate" | "Short-Lived Certificate" => continue,
                            "Static RSA Key Exchange" => {
                                println!("  │  ⚠️  Static RSA — no forward secrecy, all sessions decryptable");
                            }
                            _ => {
                                println!("  │  ⚠️  {}", finding.category);
                            }
                        }
                    }

                    // Remediation section
                    println!("  │");
                    println!("  │  🔧 Remediation:");

                    let mut kex_remediations: Vec<&str> = Vec::new();
                    let mut cert_remediations: Vec<&str> = Vec::new();
                    let mut other_remediations: Vec<&str> = Vec::new();

                    for finding in &hndl.findings {
                        match finding.category.as_str() {
                            "No PQC Key Exchange" => {
                                kex_remediations.push("Deploy X25519MLKEM768 on TLS 1.3");
                            }
                            "TLS 1.2 Fallback Available" => {
                                kex_remediations.push("Plan TLS 1.2 deprecation per NIST SP 800-52 Rev. 2");
                                if let Some(scsv) = scsv_supported {
                                    if !*scsv {
                                        kex_remediations.push("Enable TLS Fallback SCSV (RFC 7507) to detect downgrade attempts");
                                    }
                                }
                            }
                            "TLS 1.2 Static RSA Key Exchange" => {
                                kex_remediations.push("Remove static RSA cipher suites — use ECDHE for forward secrecy");
                            }
                            "RSA-2048 Certificate" | "RSA Certificate" => {
                                cert_remediations.push("Adopt ML-DSA certificates when available");
                            }
                            "ECDSA Certificate" => {
                                cert_remediations.push("Adopt ML-DSA certificates when available");
                            }
                            "PQC Certificate" => {
                                // No remediation needed — cert is already quantum-safe
                            }
                            "PQC Advertised But Not Negotiated" => {
                                other_remediations.push("Verify PQC group priority in server configuration");
                            }
                            "Deprecated PQC Algorithm" => {
                                kex_remediations.push("Migrate from Kyber draft to ML-KEM (X25519MLKEM768)");
                            }
                            "Downgrade Amplifies Risk" => {
                                other_remediations.push("Investigate why server prefers classical over PQC when both offered");
                            }
                            _ => {}
                        }
                    }

                    if !kex_remediations.is_empty() {
                        println!("  │     Key Exchange:");
                        for r in &kex_remediations {
                            println!("  │        - {}", r);
                        }
                    }
                    if !cert_remediations.is_empty() {
                        println!("  │     Certificates:");
                        for r in &cert_remediations {
                            println!("  │        - {}", r);
                        }
                    }
                    for r in &other_remediations {
                        println!("  │  🔧 {}", r);
                    }
                }

                println!("  └────────────────────────────────────────");
                println!();
            }
            ScanResult::Ssh {
                targetspec,
                error,
                pqc_supported,
                pqc_algos,
                nonpqc_algos,
                hndl_assessment,
                ..
            } => {
                println!("  ┌─ {} (SSH)", targetspec);

                if let Some(err) = error {
                    println!("  │  Error: {}", err);
                    println!("  └────────────────────────────────────────");
                    println!();
                    continue;
                }

                if *pqc_supported {
                    let algos = pqc_algos.as_ref().map(|a| {
                        let mut s = a.clone();
                        s.sort();
                        s.join(", ")
                    }).unwrap_or_default();
                    println!("  │  PQC Support:    ✅ Yes ({})", algos);
                } else {
                    println!("  │  PQC Support:    ❌ No");
                }
                if let Some(hndl) = hndl_assessment {
                    let risk_icon = match hndl.risk_level {
                        crate::hndl::HndlSeverity::Critical => "🔴",
                        crate::hndl::HndlSeverity::High => "🟠",
                        crate::hndl::HndlSeverity::Medium => "🟡",
                        crate::hndl::HndlSeverity::Low => "🟢",
                        crate::hndl::HndlSeverity::Info => "✅",
                    };
                    println!("  │");
                    println!("  │  {} Risk Assessment: {}", risk_icon, hndl.risk_level);

                    // Show findings
                    for finding in &hndl.findings {
                        let icon = match finding.severity {
                            crate::hndl::HndlSeverity::Info => "✅",
                            _ => "⚠️ ",
                        };
                        match finding.category.as_str() {
                            "No PQC Key Exchange" => {
                                println!("  │  {} No PQC — all sessions quantum-decryptable", icon);
                            }
                            "PQC KEX Advertised (Hybrid)" | "PQC KEX Advertised" => {
                                println!("  │  {} PQC KEX active — sessions quantum-resistant", icon);
                            }
                            "Weak Classical KEX Available" => {
                                println!("  │  {} Vulnerable KEX algorithms (weak):", icon);
                                if let Some(algos) = nonpqc_algos {
                                    for algo in algos {
                                        if !algo.starts_with("kex-strict-") && !algo.starts_with("ext-info-") {
                                            println!("  │        - {}", algo);
                                        }
                                    }
                                }
                            }
                            "Classical KEX Fallback Available" => {
                                println!("  │  {} Vulnerable KEX algorithms:", icon);
                                if let Some(algos) = nonpqc_algos {
                                    for algo in algos {
                                        if !algo.starts_with("kex-strict-") && !algo.starts_with("ext-info-") {
                                            println!("  │        - {}", algo);
                                        }
                                    }
                                }
                            }
                            _ => {
                                println!("  │  {} {}", icon, finding.category);
                            }
                        }
                    }

                    // Remediation
                    let mut remediations: Vec<&str> = Vec::new();
                    for finding in &hndl.findings {
                        match finding.category.as_str() {
                            "No PQC Key Exchange" => {
                                remediations.push("Enable sntrup761x25519-sha512 or mlkem768x25519-sha256");
                            }
                            "Weak Classical KEX Available" => {
                                remediations.push("Remove weak classical KEX (diffie-hellman-group14)");
                            }
                            "Classical KEX Fallback Available" => {
                                remediations.push("Prioritize PQC KEX in server configuration");
                            }
                            _ => {}
                        }
                    }
                    if !remediations.is_empty() {
                        println!("  │");
                        println!("  │  🔧 Remediation:");
                        for r in &remediations {
                            println!("  │        - {}", r);
                        }
                    }
                }
                println!("  └────────────────────────────────────────");
                println!();
            }
            ScanResult::Done => {}
        }
    }

    println!("═══════════════════════════════════════════════════════════════");
}

#[derive(RustEmbed)]
#[folder = "$CARGO_MANIFEST_DIR/support/templates/"]
struct EmbeddedResources;

const DEFAULT_NUM_THREADS: usize = 8;

fn output_args(file_type: &str) -> Vec<clap::Arg> {
    vec![Arg::new("output")
        .short('o')
        .value_name("FILE")
        .long("output")
        .help(format!("{} file to write results to", file_type))
        .required(false)
        .action(ArgAction::Set)]
}

fn num_threads_arg() -> clap::Arg {
    Arg::new("num-threads")
        .long("num-threads")
        .default_value(format!("{}", DEFAULT_NUM_THREADS))
        .value_parser(clap::value_parser!(usize))
        .help("Number of scan threads to use")
}

fn target_args() -> Vec<clap::Arg> {
    vec![
        Arg::new("target")
            .short('t')
            .long("target")
            .value_name("HOST:PORT")
            .help("HOST:PORT")
            .conflicts_with("target-list")
            .action(ArgAction::Set),
        Arg::new("target-list")
            .short('T')
            .value_name("FILE")
            .long("target-list")
            .help("File listing HOST:PORT entries")
            .conflicts_with("target")
            .action(ArgAction::Set)
            .value_parser(clap::value_parser!(PathBuf)),
    ]
}

fn get_targets(matches: &ArgMatches, default_port: Option<u16>) -> Result<Vec<Target>> {
    match matches.get_one::<String>("target") {
        Some(t) => Ok(vec![parse_single_target(t, default_port)?]),
        None => {
            let f = matches.get_one::<PathBuf>("target-list");
            if f.is_none() {
                return Err(anyhow!("specify -t or -T"));
            }
            let file = File::open(f.unwrap())?;
            let reader = BufReader::new(file);
            let mut line_no = 0;
            let mut targets: Vec<Target> = Vec::new();

            for line in reader.lines() {
                let line = line?;

                line_no += 1;

                if line.is_empty() || line.starts_with('#') {
                    continue;
                }

                match parse_single_target(&line, default_port) {
                    Ok(t) => targets.push(t),
                    Err(e) => {
                        return Err(anyhow!("Parsing line {line_no} ({line}) failed. {e}"));
                    }
                }
            }
            Ok(targets)
        }
    }
}

fn generate_report_from_scan(output_file: &str, scan: &Scan) -> Result<()> {
    use std::io::Write;
    log::debug!("Generating HTML report");

    let html_file = EmbeddedResources::get("template.html").unwrap();
    let template = std::str::from_utf8(html_file.data.as_ref())?;

    let dt = Utc::now().format("%Y-%m-%d %H:%M:%S %Z").to_string();
    let scan_data = serde_json::json!({ "results": &scan.results });

    let output = template
        .replace("{{ title }}", &dt)
        .replace("{{ scan_data | safe }}", &scan_data.to_string());

    let f = File::create(output_file)?;
    let mut w = BufWriter::new(f);
    w.write_all(output.as_bytes())?;

    log::info!("HTML report written to {}", output_file);
    Ok(())
}

fn write_csv(path: &str, scan: &Scan) -> Result<()> {
    use std::io::Write;
    let f = File::create(path)?;
    let mut w = BufWriter::new(f);

    writeln!(w, "host,port,protocol,pqc_supported,pqc_algorithms,negotiated_group,negotiated_cipher,tls12_fallback,risk_level,scsv_supported,cert_key_type,cert_key_bits,cert_validity_days")?;

    for result in &scan.results {
        match result {
            ScanResult::Tls {
                targetspec, pqc_supported, pqc_algos, hybrid_algos,
                negotiated_group, negotiated_cipher_suite,
                handshake_tls12, hndl_assessment, scsv_supported, handshake_pqc, ..
            } => {
                let mut algos = Vec::new();
                if let Some(p) = pqc_algos { algos.extend(p.iter().cloned()); }
                if let Some(h) = hybrid_algos { algos.extend(h.iter().cloned()); }
                algos.sort();

                let tls12 = handshake_tls12.as_ref().map(|h| h.completed).unwrap_or(false);
                let hndl = hndl_assessment.as_ref().map(|h| format!("{}", h.risk_level)).unwrap_or_default();
                let scsv = scsv_supported.map(|s| s.to_string()).unwrap_or_default();

                let (kt, kb, vd) = handshake_pqc.as_ref().map(|h| {
                    (
                        h.peer_certificate_key_type.clone().unwrap_or_default(),
                        h.peer_certificate_key_bits.map(|b| b.to_string()).unwrap_or_default(),
                        h.peer_certificate_validity_days.map(|d| d.to_string()).unwrap_or_default(),
                    )
                }).unwrap_or_default();

                writeln!(w, "{},{},TLS,{},{},{},{},{},{},{},{},{},{}",
                    targetspec.host, targetspec.port, pqc_supported,
                    algos.join(";"),
                    negotiated_group.as_deref().unwrap_or(""),
                    negotiated_cipher_suite.as_deref().unwrap_or(""),
                    tls12, hndl, scsv, kt, kb, vd,
                )?;
            }
            ScanResult::Ssh {
                targetspec, pqc_supported, pqc_algos, hndl_assessment, ..
            } => {
                let algos = pqc_algos.as_ref().map(|a| {
                    let mut s = a.clone(); s.sort(); s.join(";")
                }).unwrap_or_default();
                let hndl = hndl_assessment.as_ref().map(|h| format!("{}", h.risk_level)).unwrap_or_default();

                writeln!(w, "{},{},SSH,{},{},,,,,{},,,",
                    targetspec.host, targetspec.port, pqc_supported, algos, hndl,
                )?;
            }
            ScanResult::Done => {}
        }
    }

    log::info!("CSV results written to {}", path);
    Ok(())
}

fn write_xml(path: &str, scan: &Scan) -> Result<()> {
    use std::io::Write;
    let f = File::create(path)?;
    let mut w = BufWriter::new(f);

    writeln!(w, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>")?;
    writeln!(w, "<pqcscan version=\"{}\" start=\"{}\" end=\"{}\">",
        scan.version, scan.start_time, scan.end_time)?;

    for result in &scan.results {
        match result {
            ScanResult::Tls {
                targetspec, pqc_supported, pqc_algos, hybrid_algos,
                negotiated_group, negotiated_cipher_suite,
                handshake_tls12, hndl_assessment, scsv_supported, handshake_pqc,
                error, ..
            } => {
                writeln!(w, "  <target host=\"{}\" port=\"{}\" protocol=\"TLS\">",
                    targetspec.host, targetspec.port)?;
                if let Some(err) = error {
                    writeln!(w, "    <error>{}</error>", escape_xml(err))?;
                } else {
                    writeln!(w, "    <pqc_supported>{}</pqc_supported>", pqc_supported)?;

                    let mut algos = Vec::new();
                    if let Some(p) = pqc_algos { algos.extend(p.iter().cloned()); }
                    if let Some(h) = hybrid_algos { algos.extend(h.iter().cloned()); }
                    algos.sort();
                    if !algos.is_empty() {
                        writeln!(w, "    <pqc_algorithms>")?;
                        for algo in &algos {
                            writeln!(w, "      <algorithm>{}</algorithm>", algo)?;
                        }
                        writeln!(w, "    </pqc_algorithms>")?;
                    }

                    if let Some(g) = negotiated_group {
                        writeln!(w, "    <negotiated_group>{}</negotiated_group>", g)?;
                    }
                    if let Some(c) = negotiated_cipher_suite {
                        writeln!(w, "    <negotiated_cipher>{}</negotiated_cipher>", c)?;
                    }

                    let tls12 = handshake_tls12.as_ref().map(|h| h.completed).unwrap_or(false);
                    writeln!(w, "    <tls12_fallback>{}</tls12_fallback>", tls12)?;

                    if let Some(scsv) = scsv_supported {
                        writeln!(w, "    <scsv_supported>{}</scsv_supported>", scsv)?;
                    }

                    if let Some(hs) = handshake_pqc {
                        if hs.peer_certificate_key_type.is_some() {
                            writeln!(w, "    <certificate>")?;
                            if let Some(kt) = &hs.peer_certificate_key_type {
                                writeln!(w, "      <key_type>{}</key_type>", kt)?;
                            }
                            if let Some(kb) = hs.peer_certificate_key_bits {
                                writeln!(w, "      <key_bits>{}</key_bits>", kb)?;
                            }
                            if let Some(vd) = hs.peer_certificate_validity_days {
                                writeln!(w, "      <validity_days>{}</validity_days>", vd)?;
                            }
                            writeln!(w, "    </certificate>")?;
                        }
                    }

                    if let Some(assessment) = hndl_assessment {
                        writeln!(w, "    <risk_assessment level=\"{}\">", assessment.risk_level)?;
                        for finding in &assessment.findings {
                            writeln!(w, "      <finding severity=\"{}\" category=\"{}\">{}</finding>",
                                finding.severity, escape_xml(&finding.category), escape_xml(&finding.detail))?;
                        }
                        writeln!(w, "    </risk_assessment>")?;
                    }
                }
                writeln!(w, "  </target>")?;
            }
            ScanResult::Ssh {
                targetspec, pqc_supported, pqc_algos, nonpqc_algos,
                hndl_assessment, error, ..
            } => {
                writeln!(w, "  <target host=\"{}\" port=\"{}\" protocol=\"SSH\">",
                    targetspec.host, targetspec.port)?;
                if let Some(err) = error {
                    writeln!(w, "    <error>{}</error>", escape_xml(err))?;
                } else {
                    writeln!(w, "    <pqc_supported>{}</pqc_supported>", pqc_supported)?;

                    if let Some(algos) = pqc_algos {
                        if !algos.is_empty() {
                            writeln!(w, "    <pqc_algorithms>")?;
                            for algo in algos {
                                writeln!(w, "      <algorithm>{}</algorithm>", algo)?;
                            }
                            writeln!(w, "    </pqc_algorithms>")?;
                        }
                    }

                    if let Some(algos) = nonpqc_algos {
                        if !algos.is_empty() {
                            writeln!(w, "    <classical_algorithms>")?;
                            for algo in algos {
                                writeln!(w, "      <algorithm>{}</algorithm>", algo)?;
                            }
                            writeln!(w, "    </classical_algorithms>")?;
                        }
                    }

                    if let Some(assessment) = hndl_assessment {
                        writeln!(w, "    <risk_assessment level=\"{}\">", assessment.risk_level)?;
                        for finding in &assessment.findings {
                            writeln!(w, "      <finding severity=\"{}\" category=\"{}\">{}</finding>",
                                finding.severity, escape_xml(&finding.category), escape_xml(&finding.detail))?;
                        }
                        writeln!(w, "    </risk_assessment>")?;
                    }
                }
                writeln!(w, "  </target>")?;
            }
            ScanResult::Done => {}
        }
    }

    writeln!(w, "</pqcscan>")?;
    log::info!("XML results written to {}", path);
    Ok(())
}

fn escape_xml(s: &str) -> String {
    s.replace('&', "&amp;")
     .replace('<', "&lt;")
     .replace('>', "&gt;")
     .replace('"', "&quot;")
     .replace('\'', "&apos;")
}

fn main() -> Result<()> {
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();

    log::info!("PQCscan {} starting", crate_version!());

    let matches = Command::new("pqcscan")
        .version(crate_version!())
        .propagate_version(true)
        .subcommand_required(true)
        .arg_required_else_help(true)
        .about("Post-Quantum Cryptography Scanner - Scan SSH/TLS servers for PQC support")
        .after_help(
            "PQCscan is free BSD-licensed software by Anvil Secure Inc (https://anvilsecure.com).",
        )
        .flatten_help(true)
        .subcommand(
            Command::new("ssh-scan")
                .about("Scan SSH servers")
                .next_help_heading("Target")
                .args(target_args())
                .next_help_heading("Output")
                .args(output_args("JSON"))
                .next_help_heading("Scan Options")
                .args(vec![
                    num_threads_arg(),
                    Arg::new("report")
                        .long("report")
                        .value_name("FILE")
                        .required(false)
                        .action(ArgAction::Set)
                        .help("Generate an HTML report directly from scan results"),
                ])
                .disable_help_flag(true)
                .disable_version_flag(true),
        )
        .subcommand(
            Command::new("tls-scan")
                .about("Scan TLS servers")
                .next_help_heading("Target")
                .args(target_args())
                .next_help_heading("Output")
                .args(output_args("JSON"))
                .next_help_heading("Scan Options")
                .args(vec![
                    num_threads_arg(),
                    Arg::new("only-hybrid-algos")
                        .long("only-hybrid-algos")
                        .required(false)
                        .action(ArgAction::SetTrue)
                        .help("Limit scan to PQC hybrid algorithms only"),
                    Arg::new("test-nonpqc-algos")
                        .long("test-nonpqc-algos")
                        .required(false)
                        .action(ArgAction::SetTrue)
                        .help("Test non-PQC algorithms in the scan"),
                    Arg::new("validate-handshake")
                        .long("validate-handshake")
                        .required(false)
                        .action(ArgAction::SetTrue)
                        .help("Perform full TLS handshake validation with PQC and classical configs to detect downgrade attacks"),
                    Arg::new("csv")
                        .long("csv")
                        .value_name("FILE")
                        .required(false)
                        .action(ArgAction::Set)
                        .help("Write results to a CSV file (one row per target)"),
                    Arg::new("xml")
                        .long("xml")
                        .value_name("FILE")
                        .required(false)
                        .action(ArgAction::Set)
                        .help("Write results to an XML file"),
                    Arg::new("report")
                        .long("report")
                        .value_name("FILE")
                        .required(false)
                        .action(ArgAction::Set)
                        .help("Generate an HTML report directly from scan results"),
                ])
                .disable_help_flag(true)
                .disable_version_flag(true),
        )
        .get_matches();

    let config = Config::new();

    log::debug!(
        "Configuration loaded: connection_timeout={}s, read_timeout={}s",
        config.connection_timeout,
        config.read_timeout
    );

    let mut scan = ScanOptions {
        num_threads: DEFAULT_NUM_THREADS,
        targets: vec![],
        scan_type: None,
        scan_hybrid_algos_only: false,
        scan_nonpqc_algos: false,
        validate_handshake: false,
    };

    let output_json_file: Option<&String>;
    let mut output_csv_file: Option<&String> = None;
    let mut output_xml_file: Option<&String> = None;
    let output_report_file: Option<&String>;

    match matches.subcommand() {
        Some(("tls-scan", sub_matches)) => {
            log::info!("Starting TLS scan");
            scan.targets = get_targets(sub_matches, Some(config.tls_config.default_port))?;
            log::info!("Loaded {} target(s) for TLS scan", scan.targets.len());
            scan.scan_type = Some(ScanType::Tls);
            scan.scan_hybrid_algos_only =
                *sub_matches.get_one::<bool>("only-hybrid-algos").unwrap();
            if scan.scan_hybrid_algos_only {
                log::info!("Scanning for hybrid algorithms only");
            }
            scan.scan_nonpqc_algos = *sub_matches.get_one::<bool>("test-nonpqc-algos").unwrap();
            if scan.scan_nonpqc_algos {
                log::info!("Including non-PQC algorithms in the scan");
            }
            scan.validate_handshake =
                *sub_matches.get_one::<bool>("validate-handshake").unwrap();
            if scan.validate_handshake {
                log::info!("Full handshake validation enabled");
            }
            scan.num_threads = *sub_matches.get_one::<usize>("num-threads").unwrap();
            log::info!("Using {} thread(s)", scan.num_threads);
            output_json_file = sub_matches.get_one::<String>("output");
            output_csv_file = sub_matches.get_one::<String>("csv");
            output_xml_file = sub_matches.get_one::<String>("xml");
            output_report_file = sub_matches.get_one::<String>("report");
        }
        Some(("ssh-scan", sub_matches)) => {
            log::info!("Starting SSH scan");
            scan.targets = get_targets(sub_matches, Some(config.ssh_config.default_port))?;
            log::info!("Loaded {} target(s) for SSH scan", scan.targets.len());
            scan.scan_type = Some(ScanType::Ssh);
            scan.num_threads = *sub_matches.get_one::<usize>("num-threads").unwrap();
            log::info!("Using {} thread(s)", scan.num_threads);
            output_json_file = sub_matches.get_one::<String>("output");
            output_report_file = sub_matches.get_one::<String>("report");
        }
        _ => unreachable!("somehow reached this"),
    }

    log::info!("Initializing async runtime");
    let rt = Runtime::new()?;

    log::info!("Starting scan execution");
    let results = rt.block_on(scan_runner(Arc::new(config), scan));
    rt.shutdown_background();

    log::info!("Scan completed. Total results: {}", results.results.len());
    log::info!(
        "Scan duration: {:.2}s",
        (results.end_time - results.start_time).num_milliseconds() as f64 / 1000.0
    );

    print_scan_summary(&results);

    /* write results to JSON output if requested */
    if let Some(output_file) = output_json_file {
        log::info!("Writing results to {}", output_file);
        let f = File::create(output_file)?;
        let mut writer = BufWriter::new(f);
        serde_json::to_writer_pretty(&mut writer, &results)?;
        log::info!("Results written successfully");
    }

    /* write CSV output if requested */
    if let Some(csv_file) = output_csv_file {
        write_csv(csv_file, &results)?;
    }

    /* write XML output if requested */
    if let Some(xml_file) = output_xml_file {
        write_xml(xml_file, &results)?;
    }

    /* generate HTML report if requested */
    if let Some(report_file) = output_report_file {
        generate_report_from_scan(report_file, &results)?;
    }

    log::info!("PQCscan finished");

    Ok(())
}
