use anyhow::{anyhow, Result};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, ClientConnection, DigitallySignedStruct, SignatureScheme};
use serde::{Deserialize, Serialize};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

use crate::config::Config;
use crate::utils::Target;

/// Result of a full TLS handshake validation.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct HandshakeValidation {
    pub completed: bool,
    pub negotiated_cipher_suite: Option<String>,
    pub negotiated_version: Option<String>,
    pub negotiated_group: Option<String>,
    pub peer_certificate_subject: Option<String>,
    pub peer_certificate_sig_algo: Option<String>,
    pub peer_certificate_key_type: Option<String>,
    pub peer_certificate_key_bits: Option<u32>,
    pub peer_certificate_validity_days: Option<i64>,
    pub session_tickets_received: Option<u32>,
    pub handshake_error: Option<String>,
}

/// Downgrade detection result from comparing PQC vs classical handshakes.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DowngradeCheck {
    pub pqc_offered_and_used: bool,
    pub classical_fallback_works: bool,
    pub potential_downgrade: bool,
    pub details: String,
}

/// Construct a failed HandshakeValidation with the given error message.
fn failed_validation(error: impl std::fmt::Display) -> HandshakeValidation {
    HandshakeValidation {
        completed: false,
        negotiated_cipher_suite: None,
        negotiated_version: None,
        negotiated_group: None,
        peer_certificate_subject: None,
        peer_certificate_sig_algo: None,
        peer_certificate_key_type: None,
        peer_certificate_key_bits: None,
        peer_certificate_validity_days: None,
        session_tickets_received: None,
        handshake_error: Some(error.to_string()),
    }
}

/// A certificate verifier that accepts any certificate.
/// We're scanning, not establishing trust — we want the handshake to complete
/// so we can inspect what was negotiated.
#[derive(Debug)]
struct NoVerifier;

impl ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
            SignatureScheme::ED448,
        ]
    }
}

/// Filter PQC/ML-KEM groups out of a crypto provider's key exchange groups.
fn filter_pqc_groups(provider: &mut rustls::crypto::CryptoProvider) {
    provider.kx_groups.retain(|g| {
        let name = format!("{:?}", g.name()).to_uppercase();
        !name.contains("MLKEM") && !name.contains("ML_KEM") && !name.contains("KYBER")
    });
}

/// Build a rustls ClientConfig with the given provider and protocol versions.
fn build_client_config(
    provider: rustls::crypto::CryptoProvider,
    versions: &[&'static rustls::SupportedProtocolVersion],
) -> Result<Arc<ClientConfig>> {
    let config = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(versions)
        .map_err(|e| anyhow!("Failed to configure TLS versions: {}", e))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerifier))
        .with_no_client_auth();
    Ok(Arc::new(config))
}

/// Build a ClientConfig with PQC key exchange (X25519MLKEM768) enabled.
fn build_pqc_client_config() -> Result<Arc<ClientConfig>> {
    build_client_config(
        rustls_post_quantum::provider(),
        &[&rustls::version::TLS13],
    )
}

/// Build a ClientConfig with only classical (non-PQC) key exchange groups.
fn build_classical_client_config() -> Result<Arc<ClientConfig>> {
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    filter_pqc_groups(&mut provider);
    build_client_config(provider, &[&rustls::version::TLS13])
}

/// Build a ClientConfig that offers only TLS 1.2 to test for legacy fallback.
fn build_tls12_client_config() -> Result<Arc<ClientConfig>> {
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    filter_pqc_groups(&mut provider);
    build_client_config(provider, &[&rustls::version::TLS12])
}

/// Resolve a target hostname:port to a SocketAddr.
fn resolve_target(target: &Target) -> std::result::Result<std::net::SocketAddr, String> {
    let addr_str = format!("{}:{}", target.host, target.port);
    // Try direct parse first (for IP addresses)
    if let Ok(addr) = addr_str.parse() {
        return Ok(addr);
    }
    // Fall back to DNS resolution
    use std::net::ToSocketAddrs;
    addr_str
        .to_socket_addrs()
        .map_err(|e| format!("DNS resolution failed: {}", e))?
        .next()
        .ok_or_else(|| format!("Could not resolve {}", target.host))
}

/// Perform a full TLS handshake with the given config and extract negotiation details.
fn do_handshake(
    tls_config: &Arc<ClientConfig>,
    target: &Target,
    timeout: u64,
) -> HandshakeValidation {
    let server_name = match ServerName::try_from(target.host.as_str()) {
        Ok(name) => name.to_owned(),
        Err(e) => return failed_validation(format!("Invalid server name: {}", e)),
    };

    let mut conn = match ClientConnection::new(tls_config.clone(), server_name) {
        Ok(c) => c,
        Err(e) => return failed_validation(format!("Failed to create TLS connection: {}", e)),
    };

    let addr = match resolve_target(target) {
        Ok(a) => a,
        Err(e) => return failed_validation(e),
    };

    let mut tcp = match TcpStream::connect_timeout(&addr, Duration::from_secs(timeout)) {
        Ok(s) => s,
        Err(e) => return failed_validation(format!("TCP connect failed: {}", e)),
    };

    tcp.set_read_timeout(Some(Duration::from_secs(timeout))).ok();
    tcp.set_write_timeout(Some(Duration::from_secs(timeout))).ok();

    if let Err(e) = conn.complete_io(&mut tcp) {
        return failed_validation(format!("Handshake failed: {}", e));
    }

    // Extract negotiated parameters
    let cipher_suite = conn
        .negotiated_cipher_suite()
        .map(|cs| format!("{:?}", cs.suite()));

    let version = conn
        .protocol_version()
        .map(|v| format!("{:?}", v));

    let group = conn
        .negotiated_key_exchange_group()
        .map(|g| format!("{:?}", g.name()));

    let (cert_subject, cert_sig_algo, cert_key_type, cert_key_bits, cert_validity_days) =
        match conn.peer_certificates() {
            Some(certs) if !certs.is_empty() => {
                parse_leaf_certificate(&certs[0])
            }
            _ => (None, None, None, None, None),
        };

    // Try to receive NewSessionTicket messages by reading a bit more
    // (TLS 1.3 servers send these right after the handshake completes)
    tcp.set_read_timeout(Some(Duration::from_millis(500))).ok();
    let _ = conn.complete_io(&mut tcp); // ignore errors — we just want tickets

    HandshakeValidation {
        completed: true,
        negotiated_cipher_suite: cipher_suite,
        negotiated_version: version,
        negotiated_group: group,
        peer_certificate_subject: cert_subject,
        peer_certificate_sig_algo: cert_sig_algo,
        peer_certificate_key_type: cert_key_type,
        peer_certificate_key_bits: cert_key_bits,
        peer_certificate_validity_days: cert_validity_days,
        session_tickets_received: None, // rustls doesn't expose ticket count publicly
        handshake_error: None,
    }
}

/// Parse a DER-encoded leaf certificate and extract key type, key bits,
/// signature algorithm, subject, and validity period.
fn parse_leaf_certificate(
    cert_der: &CertificateDer<'_>,
) -> (Option<String>, Option<String>, Option<String>, Option<u32>, Option<i64>) {
    use x509_parser::prelude::*;

    let (_, cert) = match X509Certificate::from_der(cert_der.as_ref()) {
        Ok(parsed) => parsed,
        Err(e) => {
            log::debug!("Failed to parse X.509 certificate: {}", e);
            return (None, None, None, None, None);
        }
    };

    // Subject (CN or full subject)
    let subject = cert
        .subject()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .map(|s| s.to_string())
        .or_else(|| Some(cert.subject().to_string()));

    // Signature algorithm
    let sig_algo = Some(format!("{}", cert.signature_algorithm.algorithm));

    // Public key type and size
    let spki = cert.public_key();
    let key_algo_oid = &spki.algorithm.algorithm;
    let (key_type, key_bits) = if key_algo_oid == &oid_registry::OID_PKCS1_RSAENCRYPTION {
        let bits = spki.parsed().ok().map(|pk| match pk {
            x509_parser::public_key::PublicKey::RSA(rsa) => rsa.key_size() as u32,
            _ => 0,
        });
        ("RSA".to_string(), bits)
    } else if key_algo_oid == &oid_registry::OID_KEY_TYPE_EC_PUBLIC_KEY {
        let curve_name = spki
            .algorithm
            .parameters
            .as_ref()
            .and_then(|p| p.as_oid().ok())
            .map(|oid| {
                if oid == oid_registry::OID_EC_P256 {
                    "P-256"
                } else if oid == oid_registry::OID_NIST_EC_P384 {
                    "P-384"
                } else if oid == oid_registry::OID_NIST_EC_P521 {
                    "P-521"
                } else {
                    "unknown-curve"
                }
            })
            .unwrap_or("unknown-curve");
        let bits = match curve_name {
            "P-256" => Some(256),
            "P-384" => Some(384),
            "P-521" => Some(521),
            _ => None,
        };
        (format!("ECDSA-{}", curve_name), bits)
    } else if key_algo_oid == &oid_registry::OID_SIG_ED25519 {
        ("Ed25519".to_string(), Some(256))
    } else if key_algo_oid == &oid_registry::OID_SIG_ED448 {
        ("Ed448".to_string(), Some(448))
    } else {
        (format!("unknown({})", key_algo_oid), None)
    };

    // Validity period in days
    let not_before = cert.validity().not_before.timestamp();
    let not_after = cert.validity().not_after.timestamp();
    let validity_days = (not_after - not_before) / 86400;

    (subject, sig_algo, Some(key_type), key_bits, Some(validity_days))
}

/// Check if a negotiated group name indicates PQC key exchange.
pub fn is_pqc_group(group: &str) -> bool {
    let g = group.to_uppercase();
    g.contains("MLKEM") || g.contains("ML_KEM") || g.contains("KYBER")
}

/// Run a full handshake validation against a target.
/// Performs three handshakes:
/// 1. With PQC groups enabled — to validate PQC negotiation
/// 2. With only classical groups — to test fallback behavior
/// 3. With TLS 1.2 only — to test legacy protocol fallback
///
/// Compares results to detect potential downgrade scenarios.
pub fn validate_handshake(
    config: &Config,
    target: &Target,
) -> (HandshakeValidation, HandshakeValidation, HandshakeValidation, DowngradeCheck) {
    // Handshake 1: PQC-enabled
    log::info!("Handshake validation: starting PQC handshake for {}", target);

    let pqc_config = match build_pqc_client_config() {
        Ok(c) => c,
        Err(e) => {
            let err = failed_validation(format!("Failed to build PQC config: {}", e));
            let downgrade = DowngradeCheck {
                pqc_offered_and_used: false,
                classical_fallback_works: false,
                potential_downgrade: false,
                details: "Could not build PQC configuration".to_string(),
            };
            return (err.clone(), err.clone(), err, downgrade);
        }
    };
    let pqc_result = do_handshake(&pqc_config, target, config.connection_timeout);
    log_handshake_result("PQC", target, &pqc_result);

    // Handshake 2: Classical-only
    log::info!("Handshake validation: starting classical-only handshake for {}", target);

    let classical_config = match build_classical_client_config() {
        Ok(c) => c,
        Err(e) => {
            let err = failed_validation(format!("Failed to build classical config: {}", e));
            let downgrade = DowngradeCheck {
                pqc_offered_and_used: false,
                classical_fallback_works: false,
                potential_downgrade: false,
                details: "Could not build classical configuration".to_string(),
            };
            return (pqc_result, err.clone(), err, downgrade);
        }
    };
    let classical_result = do_handshake(&classical_config, target, config.connection_timeout);
    log_handshake_result("classical", target, &classical_result);

    // Downgrade analysis
    let pqc_used = pqc_result.completed
        && pqc_result
            .negotiated_group
            .as_deref()
            .map(is_pqc_group)
            .unwrap_or(false);

    let classical_works = classical_result.completed;
    let potential_downgrade = pqc_result.completed && !pqc_used && classical_works;

    let details = if !pqc_result.completed && !classical_works {
        "Both PQC and classical handshakes failed — server may be unreachable or incompatible".to_string()
    } else if pqc_used && classical_works {
        format!(
            "Server negotiated PQC group ({}) when offered. Classical fallback also works ({}).",
            pqc_result.negotiated_group.as_deref().unwrap_or("unknown"),
            classical_result.negotiated_group.as_deref().unwrap_or("unknown"),
        )
    } else if pqc_used && !classical_works {
        "Server requires PQC — classical-only handshake failed. No fallback available.".to_string()
    } else if potential_downgrade {
        format!(
            "WARNING: Server chose classical group ({}) even though PQC was offered. \
             This may indicate a downgrade or server preference for classical algorithms.",
            pqc_result.negotiated_group.as_deref().unwrap_or("unknown"),
        )
    } else if !pqc_result.completed && classical_works {
        "PQC handshake failed but classical works — server may not support PQC key exchange".to_string()
    } else {
        "Unable to determine downgrade status".to_string()
    };

    let downgrade = DowngradeCheck {
        pqc_offered_and_used: pqc_used,
        classical_fallback_works: classical_works,
        potential_downgrade,
        details,
    };

    log::info!(
        "Handshake validation: downgrade check for {} — pqc_used={}, classical_fallback={}, potential_downgrade={}",
        target, pqc_used, classical_works, potential_downgrade
    );

    // Handshake 3: TLS 1.2 fallback probe
    log::info!("Handshake validation: starting TLS 1.2 fallback probe for {}", target);

    let tls12_result = match build_tls12_client_config() {
        Ok(c) => {
            let result = do_handshake(&c, target, config.connection_timeout);
            log_handshake_result("TLS 1.2", target, &result);
            result
        }
        Err(e) => {
            log::warn!("Handshake validation: could not build TLS 1.2 config: {}", e);
            failed_validation(format!("Failed to build TLS 1.2 config: {}", e))
        }
    };

    (pqc_result, classical_result, tls12_result, downgrade)
}

/// Log the result of a handshake probe.
fn log_handshake_result(label: &str, target: &Target, result: &HandshakeValidation) {
    log::info!(
        "Handshake validation: {} handshake {} for {} (cipher={}, group={})",
        label,
        if result.completed { "completed" } else { "failed" },
        target,
        result.negotiated_cipher_suite.as_deref().unwrap_or("none"),
        result.negotiated_group.as_deref().unwrap_or("none"),
    );
}
