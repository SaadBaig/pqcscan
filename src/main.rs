use anyhow::{anyhow, Result};
use chrono::prelude::*;
use clap::{crate_version, Arg, ArgAction, ArgMatches, Command};
use env_logger::Env;
use rust_embed::RustEmbed;
use serde::Serialize;
use std::collections::{BTreeSet, HashMap};
use std::fs::File;
use std::io::{BufRead, BufReader, BufWriter};
use std::path::PathBuf;
use std::sync::Arc;
use tera::{Context, Tera};
use tokio::runtime::Runtime;

mod config;
mod handshake;
mod scan;
mod ssh;
mod tls;
mod tlsconstants;
mod utils;

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
    println!("  Scanned {} target(s) in {:.2}s", results.results.len(), duration);
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
                downgrade_check,
                ..
            } => {
                println!("  ┌─ {} (TLS)", targetspec);

                if let Some(err) = error {
                    println!("  │  Error: {}", err);
                    println!("  └────────────────────────────────────────");
                    println!();
                    continue;
                }

                if *pqc_supported {
                    println!("  │  PQC Support:    ✅ Yes");
                    let mut algos = Vec::new();
                    if let Some(pqc) = pqc_algos {
                        algos.extend(pqc.iter().cloned());
                    }
                    if let Some(hybrid) = hybrid_algos {
                        algos.extend(hybrid.iter().cloned());
                    }
                    if !algos.is_empty() {
                        algos.sort();
                        println!("  │  PQC Algorithms: {}", algos.join(", "));
                    }
                } else {
                    println!("  │  PQC Support:    ❌ No");
                }

                if let Some(pqc_hs) = handshake_pqc {
                    println!("  │");
                    println!("  │  Full Handshake (PQC-enabled):");
                    if pqc_hs.completed {
                        println!("  │    Status:       ✅ Completed");
                        if let Some(ref cs) = pqc_hs.negotiated_cipher_suite {
                            println!("  │    Cipher Suite: {}", cs);
                        }
                        if let Some(ref g) = pqc_hs.negotiated_group {
                            println!("  │    Key Exchange: {}", g);
                        }
                        if let Some(ref v) = pqc_hs.negotiated_version {
                            println!("  │    TLS Version:  {}", v);
                        }
                    } else {
                        println!("  │    Status:       ❌ Failed");
                        if let Some(ref err) = pqc_hs.handshake_error {
                            println!("  │    Error:        {}", err);
                        }
                    }
                }

                if let Some(classical_hs) = handshake_classical {
                    println!("  │");
                    println!("  │  Full Handshake (Classical-only):");
                    if classical_hs.completed {
                        println!("  │    Status:       ✅ Completed");
                        if let Some(ref g) = classical_hs.negotiated_group {
                            println!("  │    Key Exchange: {}", g);
                        }
                    } else {
                        println!("  │    Status:       ❌ Failed");
                        if let Some(ref err) = classical_hs.handshake_error {
                            println!("  │    Error:        {}", err);
                        }
                    }
                }

                if let Some(dc) = downgrade_check {
                    println!("  │");
                    println!("  │  Downgrade Assessment:");
                    if dc.potential_downgrade {
                        println!("  │    ⚠️  POTENTIAL DOWNGRADE DETECTED");
                    } else if dc.pqc_offered_and_used {
                        println!("  │    ✅ PQC negotiated when offered");
                    }
                    if dc.classical_fallback_works {
                        println!("  │    ✅ Classical fallback available");
                    }
                    println!("  │    {}", dc.details);
                }

                println!("  └────────────────────────────────────────");
                println!();
            }
            ScanResult::Ssh {
                targetspec,
                error,
                pqc_supported,
                pqc_algos,
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
                    println!("  │  PQC Support:    ✅ Yes");
                    if let Some(algos) = pqc_algos {
                        let mut sorted = algos.clone();
                        sorted.sort();
                        println!("  │  PQC Algorithms: {}", sorted.join(", "));
                    }
                } else {
                    println!("  │  PQC Support:    ❌ No");
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

fn output_args(file_type: &str, req: bool) -> Vec<clap::Arg> {
    vec![Arg::new("output")
        .short('o')
        .value_name("FILE")
        .long("output")
        .help(format!("{} file to write results to", file_type))
        .required(req)
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

#[derive(Serialize)]
struct ReportResults {
    tls_results: HashMap<String, Vec<ScanResult>>,
    tls_sorted_hosts: BTreeSet<String>,
    tls_success_count: usize,
    tls_fail_count: usize,
    tls_pqc_supported_count: usize,
    tls_total_count: usize,
    ssh_results: HashMap<String, Vec<ScanResult>>,
    ssh_sorted_hosts: BTreeSet<String>,
    ssh_success_count: usize,
    ssh_fail_count: usize,
    ssh_pqc_supported_count: usize,
    ssh_total_count: usize,
    scan_windows: Vec<ScanWindow>,
}

#[derive(Serialize)]
struct ScanWindow {
    start_time: DateTime<Utc>,
    end_time: DateTime<Utc>,
    scan_type: ScanType,
}

fn create_report(output_file: &str, input_files: &[&String]) -> Result<()> {
    log::debug!("Initializing report data structures");
    let mut tls_map: HashMap<String, Vec<ScanResult>> = HashMap::new();
    let mut ssh_map: HashMap<String, Vec<ScanResult>> = HashMap::new();
    let mut tls_hosts: BTreeSet<String> = BTreeSet::new();
    let mut ssh_hosts: BTreeSet<String> = BTreeSet::new();
    let mut ssh_pqc_supported_count: usize = 0;
    let mut tls_pqc_supported_count: usize = 0;
    let mut ssh_success_count: usize = 0;
    let mut tls_success_count: usize = 0;
    let mut ssh_total_count: usize = 0;
    let mut tls_total_count: usize = 0;
    let mut scan_windows = Vec::new();

    for input_file in input_files {
        log::debug!("Opening and parsing {}", input_file);

        let file = File::open(input_file)?;
        let scan: Scan = serde_json::from_reader(file).expect("failed to open input file");

        if scan.version != crate_version!() {
            let err = format!(
                "Version mismatch: {} != {} in {}",
                scan.version,
                crate_version!(),
                input_file
            );
            log::warn!("{}", err);
            return Err(anyhow!(err));
        }

        let window = ScanWindow {
            start_time: scan.start_time,
            end_time: scan.end_time,
            scan_type: scan.scan_type,
        };
        scan_windows.push(window);

        for result in scan.results {
            match result {
                ScanResult::Ssh {
                    ref targetspec,
                    ref error,
                    pqc_supported,
                    ..
                } => {
                    ssh_hosts.insert(targetspec.host.clone());
                    let host = targetspec.host.clone();
                    if ssh_map.get(&host).is_none() {
                        ssh_map.insert(host.clone(), Vec::new());
                    }
                    let m = ssh_map.get_mut(&host).unwrap();
                    if error.is_none() {
                        ssh_success_count += 1;
                    }
                    if pqc_supported {
                        ssh_pqc_supported_count += 1;
                    }
                    ssh_total_count += 1;
                    m.push(result);
                }
                ScanResult::Tls {
                    ref targetspec,
                    ref error,
                    pqc_supported,
                    ..
                } => {
                    tls_hosts.insert(targetspec.host.clone());
                    let host = targetspec.host.clone();
                    if tls_map.get(&host).is_none() {
                        tls_map.insert(host.clone(), Vec::new());
                    }
                    let m = tls_map.get_mut(&host).unwrap();
                    if error.is_none() {
                        tls_success_count += 1;
                    }
                    if pqc_supported {
                        tls_pqc_supported_count += 1;
                    }
                    tls_total_count += 1;
                    m.push(result);
                }
                _ => {
                    panic!("Unexpected result type");
                }
            }
        }
    }

    log::debug!(
        "{} TLS results, {} SSH results",
        tls_map.len(),
        ssh_map.len()
    );

    let tls_fail_count = tls_total_count - tls_success_count;
    let ssh_fail_count = ssh_total_count - ssh_success_count;

    log::debug!(
        "TLS: {} successful, {} failed, {} PQC-enabled",
        tls_success_count,
        tls_fail_count,
        tls_pqc_supported_count
    );
    log::debug!(
        "SSH: {} successful, {} failed, {} PQC-enabled",
        ssh_success_count,
        ssh_fail_count,
        ssh_pqc_supported_count
    );

    let results: ReportResults = ReportResults {
        tls_results: tls_map,
        tls_sorted_hosts: tls_hosts,
        tls_success_count,
        tls_pqc_supported_count,
        tls_fail_count,
        tls_total_count,
        ssh_results: ssh_map,
        ssh_sorted_hosts: ssh_hosts,
        ssh_success_count,
        ssh_fail_count,
        ssh_pqc_supported_count,
        ssh_total_count,
        scan_windows,
    };

    let templates = [
        "macros.html",
        "template.html",
        "ssh_results.html",
        "tls_results.html",
        "summary.html",
    ];
    let mut tera = Tera::default();

    log::debug!("Loading HTML templates");
    for template in templates {
        let html_file = EmbeddedResources::get(template).unwrap();
        let html_data = std::str::from_utf8(html_file.data.as_ref())?;
        tera.add_raw_template(template, html_data)?;
    }

    let mut ctx = Context::from_serialize(results)?;

    let dt = Utc::now().format("%Y-%m-%d %H:%M:%S %Z").to_string();
    ctx.insert("title", &dt);

    log::trace!("Tera Template: {:?}", ctx);

    log::debug!("Rendering HTML report to {}", output_file);
    let f = File::create(output_file)?;
    tera.render_to("template.html", &ctx, f)?;
    log::info!("HTML report written to {}", output_file);

    Ok(())
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
                .args(output_args("JSON", false))
                .next_help_heading("Scan Options")
                .args(vec![num_threads_arg()])
                .disable_help_flag(true)
                .disable_version_flag(true),
        )
        .subcommand(
            Command::new("tls-scan")
                .about("Scan TLS servers")
                .next_help_heading("Target")
                .args(target_args())
                .next_help_heading("Output")
                .args(output_args("JSON", false))
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
                ])
                .disable_help_flag(true)
                .disable_version_flag(true),
        )
        .subcommand(
            Command::new("create-report")
                .about("Convert JSON results to HTML report")
                .next_help_heading("Input")
                .args(vec![Arg::new("input")
                    .short('i')
                    .long("input")
                    .value_name("JSON file")
                    .help("JSON file(s) containing scan results ")
                    .num_args(0..)])
                .next_help_heading("Output")
                .args(output_args("HTML", true))
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

    let mut output_json_file: Option<&String> = None;

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
        }
        Some(("ssh-scan", sub_matches)) => {
            log::info!("Starting SSH scan");
            scan.targets = get_targets(sub_matches, Some(config.ssh_config.default_port))?;
            log::info!("Loaded {} target(s) for SSH scan", scan.targets.len());
            scan.scan_type = Some(ScanType::Ssh);
            scan.num_threads = *sub_matches.get_one::<usize>("num-threads").unwrap();
            log::info!("Using {} thread(s)", scan.num_threads);
            output_json_file = sub_matches.get_one::<String>("output");
        }
        Some(("create-report", sub_matches)) => {
            log::info!("Creating HTML report from JSON results");
            let input_files: Vec<_> = sub_matches
                .get_many::<String>("input")
                .ok_or(anyhow!(
                    "Need at least one input JSON file to convert into a report"
                ))?
                .collect();
            log::info!("Processing {} input file(s)", input_files.len());
            create_report(
                sub_matches.get_one::<String>("output").unwrap(),
                &input_files,
            )?;
            log::info!("Report created successfully");
        }
        _ => unreachable!("somehow reached this"),
    }

    /* perform scan if requested */
    if scan.scan_type.is_some() {
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
        if output_json_file.is_some() {
            let output_file = output_json_file.unwrap();
            log::info!("Writing results to {}", output_file);
            let f = File::create(output_file)?;
            let mut writer = BufWriter::new(f);
            serde_json::to_writer_pretty(&mut writer, &results)?;
            log::info!("Results written successfully");
        }
    }

    log::info!("PQCscan finished");

    Ok(())
}
