//! Harvest Now, Decrypt Later (HNDL) risk assessment.
//!
//! Analyzes TLS configuration to determine whether captured traffic
//! could be decrypted by a future quantum-capable adversary.

use serde::{Deserialize, Serialize};

use crate::handshake::{self, DowngradeCheck, HandshakeValidation};

/// Individual risk finding from HNDL analysis.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct HndlFinding {
    pub severity: HndlSeverity,
    pub category: String,
    pub detail: String,
}

/// Severity levels for HNDL risk findings.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum HndlSeverity {
    /// Informational — no direct risk
    Info,
    /// Low risk — minor concern
    Low,
    /// Medium risk — should be addressed
    Medium,
    /// High risk — significant HNDL exposure
    High,
    /// Critical — traffic is actively harvestable and quantum-decryptable
    Critical,
}

impl std::fmt::Display for HndlSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HndlSeverity::Info => write!(f, "INFO"),
            HndlSeverity::Low => write!(f, "LOW"),
            HndlSeverity::Medium => write!(f, "MEDIUM"),
            HndlSeverity::High => write!(f, "HIGH"),
            HndlSeverity::Critical => write!(f, "CRITICAL"),
        }
    }
}

/// Complete HNDL risk assessment for a target.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct HndlAssessment {
    pub risk_level: HndlSeverity,
    pub quantum_vulnerable: bool,
    pub findings: Vec<HndlFinding>,
    pub summary: String,
}

/// Input data collected from various scan phases for HNDL analysis.
pub struct HndlInput<'a> {
    pub pqc_supported: bool,
    pub handshake_pqc: Option<&'a HandshakeValidation>,
    pub handshake_classical: Option<&'a HandshakeValidation>,
    pub handshake_tls12: Option<&'a HandshakeValidation>,
    pub downgrade_check: Option<&'a DowngradeCheck>,
    pub cert_key_type: Option<&'a str>,
    pub cert_key_bits: Option<u32>,
    pub cert_validity_days: Option<i64>,
}

/// Run the full HNDL risk assessment.
pub fn assess_hndl_risk(input: &HndlInput) -> HndlAssessment {
    let mut findings = Vec::new();

    check_pqc_key_exchange(input, &mut findings);
    check_tls12_fallback(input, &mut findings);
    check_forward_secrecy(input, &mut findings);
    check_certificate_risks(input, &mut findings);
    check_static_rsa(input, &mut findings);
    check_downgrade_risk(input, &mut findings);

    // Determine overall risk level (highest finding wins)
    let risk_level = findings
        .iter()
        .map(|f| f.severity.clone())
        .max()
        .unwrap_or(HndlSeverity::Info);

    let quantum_vulnerable = risk_level >= HndlSeverity::High;

    let summary = build_summary(&risk_level, &findings);

    HndlAssessment {
        risk_level,
        quantum_vulnerable,
        findings,
        summary,
    }
}

/// Run HNDL risk assessment for an SSH target based on advertised KEX algorithms.
pub fn assess_ssh_hndl_risk(pqc_supported: bool, pqc_algos: &[String], nonpqc_algos: &[String]) -> HndlAssessment {
    let mut findings = Vec::new();

    if !pqc_supported {
        findings.push(HndlFinding {
            severity: HndlSeverity::Critical,
            category: "No PQC Key Exchange".to_string(),
            detail: "SSH server does not advertise any post-quantum KEX algorithms. \
                     All captured SSH sessions can be decrypted by a quantum-capable \
                     adversary with a recording of the traffic."
                .to_string(),
        });
    } else {
        let hybrid = pqc_algos.iter().any(|a| a.contains("sntrup") || a.contains("x25519"));
        if hybrid {
            findings.push(HndlFinding {
                severity: HndlSeverity::Info,
                category: "PQC KEX Advertised (Hybrid)".to_string(),
                detail: format!(
                    "SSH server advertises hybrid PQC KEX: {}. Sessions using these \
                     algorithms are quantum-resistant.",
                    pqc_algos.join(", ")
                ),
            });
        } else {
            findings.push(HndlFinding {
                severity: HndlSeverity::Info,
                category: "PQC KEX Advertised".to_string(),
                detail: format!(
                    "SSH server advertises PQC KEX: {}.",
                    pqc_algos.join(", ")
                ),
            });
        }
    }

    // Check if classical-only KEX algorithms are also present (fallback risk)
    if pqc_supported && !nonpqc_algos.is_empty() {
        let has_weak = nonpqc_algos.iter().any(|a| {
            a.contains("diffie-hellman-group14") || a.contains("diffie-hellman-group1")
        });
        if has_weak {
            findings.push(HndlFinding {
                severity: HndlSeverity::High,
                category: "Weak Classical KEX Available".to_string(),
                detail: "SSH server also advertises weak classical KEX algorithms \
                         (e.g. diffie-hellman-group14). A downgrade attack could force \
                         sessions to use quantum-vulnerable key exchange."
                    .to_string(),
            });
        } else {
            findings.push(HndlFinding {
                severity: HndlSeverity::Medium,
                category: "Classical KEX Fallback Available".to_string(),
                detail: "SSH server advertises both PQC and classical KEX algorithms. \
                         Classical algorithms are quantum-vulnerable but provide \
                         backward compatibility."
                    .to_string(),
            });
        }
    }

    let risk_level = findings
        .iter()
        .map(|f| f.severity.clone())
        .max()
        .unwrap_or(HndlSeverity::Info);

    let quantum_vulnerable = risk_level >= HndlSeverity::High;
    let summary = build_summary(&risk_level, &findings);

    HndlAssessment {
        risk_level,
        quantum_vulnerable,
        findings,
        summary,
    }
}

/// Check 1: Is PQC key exchange negotiated?
fn check_pqc_key_exchange(input: &HndlInput, findings: &mut Vec<HndlFinding>) {
    if !input.pqc_supported {
        findings.push(HndlFinding {
            severity: HndlSeverity::Critical,
            category: "No PQC Key Exchange".to_string(),
            detail: "Server does not support post-quantum key exchange. All captured TLS sessions \
                     can be decrypted by a quantum-capable adversary with a recording of the traffic."
                .to_string(),
        });
        return;
    }

    // PQC is supported — check if it's actually negotiated in the full handshake
    if let Some(pqc_hs) = input.handshake_pqc {
        if pqc_hs.completed {
            let group = pqc_hs.negotiated_group.as_deref().unwrap_or("");
            if handshake::is_pqc_group(group)
            {
                findings.push(HndlFinding {
                    severity: HndlSeverity::Info,
                    category: "PQC Key Exchange Active".to_string(),
                    detail: format!(
                        "Server negotiates PQC key exchange ({}) — TLS 1.3 sessions are \
                         quantum-resistant for key exchange.",
                        group
                    ),
                });
            } else {
                findings.push(HndlFinding {
                    severity: HndlSeverity::High,
                    category: "PQC Advertised But Not Negotiated".to_string(),
                    detail: format!(
                        "Server advertises PQC support but negotiated classical group ({}) \
                         in full handshake. Traffic is quantum-vulnerable.",
                        group
                    ),
                });
            }
        }
    }
}

/// Check 2: Does the server accept TLS 1.2 connections?
fn check_tls12_fallback(input: &HndlInput, findings: &mut Vec<HndlFinding>) {
    if let Some(tls12_hs) = input.handshake_tls12 {
        if tls12_hs.completed {
            let cipher = tls12_hs
                .negotiated_cipher_suite
                .as_deref()
                .unwrap_or("unknown");
            let version = tls12_hs
                .negotiated_version
                .as_deref()
                .unwrap_or("unknown");

            // Check if the TLS 1.2 cipher uses RSA key exchange (no forward secrecy)
            let cipher_upper = cipher.to_uppercase();
            if cipher_upper.contains("TLS_RSA_") && !cipher_upper.contains("ECDHE")
                && !cipher_upper.contains("DHE")
            {
                findings.push(HndlFinding {
                    severity: HndlSeverity::Critical,
                    category: "TLS 1.2 Static RSA Key Exchange".to_string(),
                    detail: format!(
                        "Server accepts TLS 1.2 with static RSA key exchange ({}). \
                         No forward secrecy — compromising the server's RSA private key \
                         (trivial for a quantum computer) decrypts ALL past recorded sessions.",
                        cipher
                    ),
                });
            } else if cipher_upper.contains("DHE") || cipher_upper.contains("ECDHE") {
                findings.push(HndlFinding {
                    severity: HndlSeverity::High,
                    category: "TLS 1.2 Fallback Available".to_string(),
                    detail: format!(
                        "Server accepts TLS 1.2 fallback ({}, {}). While forward secrecy \
                         is present, the classical DH/ECDH key exchange is quantum-vulnerable. \
                         An attacker can downgrade connections to TLS 1.2 and harvest traffic.",
                        version, cipher
                    ),
                });
            } else {
                findings.push(HndlFinding {
                    severity: HndlSeverity::High,
                    category: "TLS 1.2 Fallback Available".to_string(),
                    detail: format!(
                        "Server accepts TLS 1.2 ({}, {}). Older protocol versions lack \
                         PQC key exchange support entirely.",
                        version, cipher
                    ),
                });
            }
        } else {
            findings.push(HndlFinding {
                severity: HndlSeverity::Info,
                category: "TLS 1.2 Not Supported".to_string(),
                detail: "Server does not accept TLS 1.2 connections — no legacy fallback path."
                    .to_string(),
            });
        }
    }
}

/// Check 3: Forward secrecy strength of the classical handshake.
fn check_forward_secrecy(input: &HndlInput, findings: &mut Vec<HndlFinding>) {
    if let Some(classical_hs) = input.handshake_classical {
        if !classical_hs.completed {
            return;
        }
        let group = classical_hs.negotiated_group.as_deref().unwrap_or("");
        let group_upper = group.to_uppercase();

        // Weak groups that offer less quantum resistance time
        if group_upper.contains("SECP256") || group_upper.contains("X25519") {
            findings.push(HndlFinding {
                severity: HndlSeverity::Medium,
                category: "Standard Classical Key Exchange".to_string(),
                detail: format!(
                    "Classical fallback uses {} (~128-bit classical security). \
                     This is the minimum acceptable strength but offers less margin \
                     against early quantum computers.",
                    group
                ),
            });
        } else if group_upper.contains("SECP384") || group_upper.contains("X448") {
            findings.push(HndlFinding {
                severity: HndlSeverity::Low,
                category: "Strong Classical Key Exchange".to_string(),
                detail: format!(
                    "Classical fallback uses {} (~192-bit classical security). \
                     Stronger classical groups provide more time before quantum \
                     computers can break them.",
                    group
                ),
            });
        } else if group_upper.contains("FFDHE") {
            // Finite field DH — generally weaker against quantum
            findings.push(HndlFinding {
                severity: HndlSeverity::High,
                category: "Finite Field DH Key Exchange".to_string(),
                detail: format!(
                    "Classical fallback uses finite field Diffie-Hellman ({}). \
                     FFDHE groups are more vulnerable to quantum attacks than ECDH \
                     due to Shor's algorithm efficiency on discrete log problems.",
                    group
                ),
            });
        }
    }
}

/// Check 4: Certificate key type and size risks.
fn check_certificate_risks(input: &HndlInput, findings: &mut Vec<HndlFinding>) {
    if let Some(key_type) = input.cert_key_type {
        let key_upper = key_type.to_uppercase();

        if key_upper.contains("RSA") {
            let bits = input.cert_key_bits.unwrap_or(0);
            if bits > 0 && bits <= 2048 {
                findings.push(HndlFinding {
                    severity: HndlSeverity::High,
                    category: "RSA-2048 Certificate".to_string(),
                    detail: format!(
                        "Server uses RSA-{} certificate. RSA-2048 is estimated to be \
                         breakable by a quantum computer with ~4000 logical qubits. \
                         Certificate authentication can be forged post-quantum.",
                        bits
                    ),
                });
            } else if bits > 2048 {
                findings.push(HndlFinding {
                    severity: HndlSeverity::Medium,
                    category: "RSA Certificate".to_string(),
                    detail: format!(
                        "Server uses RSA-{} certificate. Larger RSA keys provide more \
                         time but are still quantum-vulnerable.",
                        bits
                    ),
                });
            }
        } else if key_upper.contains("ECDSA") || key_upper.contains("EC") {
            findings.push(HndlFinding {
                severity: HndlSeverity::Medium,
                category: "ECDSA Certificate".to_string(),
                detail: format!(
                    "Server uses {} certificate. ECDSA is quantum-vulnerable but \
                     requires fewer qubits to break than equivalent RSA. Certificate \
                     authentication can be forged post-quantum.",
                    key_type
                ),
            });
        }
    }

    // Check certificate validity period
    if let Some(days) = input.cert_validity_days {
        if days > 365 {
            findings.push(HndlFinding {
                severity: HndlSeverity::Medium,
                category: "Long-Lived Certificate".to_string(),
                detail: format!(
                    "Certificate validity period is {} days ({:.1} years). Long-lived \
                     certificates extend the window during which a quantum adversary \
                     could impersonate the server using a forged certificate.",
                    days,
                    days as f64 / 365.0
                ),
            });
        } else if days > 0 {
            findings.push(HndlFinding {
                severity: HndlSeverity::Info,
                category: "Short-Lived Certificate".to_string(),
                detail: format!(
                    "Certificate validity period is {} days. Shorter validity reduces \
                     the impersonation window.",
                    days
                ),
            });
        }
    }
}

/// Check 5: Static RSA key exchange (no forward secrecy at all).
fn check_static_rsa(input: &HndlInput, findings: &mut Vec<HndlFinding>) {
    // Check the TLS 1.3 cipher suites — these always use ephemeral key exchange,
    // so static RSA is only a concern in TLS 1.2 (handled in check_tls12_fallback).
    // Here we check if the classical handshake negotiated something without ECDHE/DHE.
    if let Some(classical_hs) = input.handshake_classical {
        if classical_hs.completed {
            let cipher = classical_hs
                .negotiated_cipher_suite
                .as_deref()
                .unwrap_or("");
            let cipher_upper = cipher.to_uppercase();

            // TLS 1.3 cipher suites always have forward secrecy, so only flag TLS 1.2
            let version = classical_hs
                .negotiated_version
                .as_deref()
                .unwrap_or("");
            if version.contains("1.2") || version.contains("0x0303") {
                if cipher_upper.starts_with("TLS_RSA_")
                    && !cipher_upper.contains("ECDHE")
                    && !cipher_upper.contains("DHE")
                {
                    findings.push(HndlFinding {
                        severity: HndlSeverity::Critical,
                        category: "Static RSA Key Exchange".to_string(),
                        detail: format!(
                            "Classical handshake negotiated static RSA cipher ({}). \
                             No forward secrecy — a single RSA key compromise decrypts \
                             ALL recorded sessions. This is the highest HNDL risk.",
                            cipher
                        ),
                    });
                }
            }
        }
    }
}

/// Check 6: Downgrade attack risk amplifies HNDL exposure.
fn check_downgrade_risk(input: &HndlInput, findings: &mut Vec<HndlFinding>) {
    if let Some(dc) = input.downgrade_check {
        if dc.potential_downgrade {
            findings.push(HndlFinding {
                severity: HndlSeverity::High,
                category: "Downgrade Amplifies HNDL Risk".to_string(),
                detail: "Server chose classical key exchange even when PQC was offered. \
                         An active attacker could force all connections to use \
                         quantum-vulnerable key exchange, making all traffic harvestable."
                    .to_string(),
            });
        }
    }
}

/// Build a human-readable summary from the findings.
fn build_summary(risk_level: &HndlSeverity, findings: &[HndlFinding]) -> String {
    let critical_count = findings
        .iter()
        .filter(|f| f.severity == HndlSeverity::Critical)
        .count();
    let high_count = findings
        .iter()
        .filter(|f| f.severity == HndlSeverity::High)
        .count();

    match risk_level {
        HndlSeverity::Critical => format!(
            "CRITICAL HNDL RISK: Traffic captured today is decryptable post-quantum. \
             {} critical and {} high severity findings.",
            critical_count, high_count
        ),
        HndlSeverity::High => format!(
            "HIGH HNDL RISK: Significant quantum vulnerability. {} high severity findings. \
             Captured traffic has limited protection against future quantum decryption.",
            high_count
        ),
        HndlSeverity::Medium => {
            "MEDIUM HNDL RISK: Some quantum-vulnerable configurations detected. \
             PQC key exchange may be active but other weaknesses exist."
                .to_string()
        }
        HndlSeverity::Low => {
            "LOW HNDL RISK: Strong configuration with minor concerns. \
             PQC key exchange is active and classical fallback is robust."
                .to_string()
        }
        HndlSeverity::Info => {
            "MINIMAL HNDL RISK: Server has strong post-quantum protections in place."
                .to_string()
        }
    }
}
