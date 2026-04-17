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

/// Result of a full TLS handshake validation
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct HandshakeValidation {
    pub completed: bool,
    pub negotiated_cipher_suite: Option<String>,
    pub negotiated_version: Option<String>,
    pub negotiated_group: Option<String>,
    pub peer_certificate_subject: Option<String>,
    pub peer_certificate_sig_algo: Option<String>,
    pub handshake_error: Option<String>,
}

/// Downgrade detection result from comparing PQC-only vs classical-only handshakes
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DowngradeCheck {
    pub pqc_offered_and_used: bool,
    pub classical_fallback_works: bool,
    pub potential_downgrade: bool,
    pub details: String,
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

/// Build a rustls ClientConfig using the post-quantum crypto provider.
/// This enables ML-KEM hybrid key exchange (X25519MLKEM768) alongside classical groups.
fn build_pqc_client_config() -> Result<Arc<ClientConfig>> {
    let provider = rustls_post_quantum::provider();
    let config = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| anyhow!("Failed to set TLS versions: {}", e))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerifier))
        .with_no_client_auth();
    Ok(Arc::new(config))
}

/// Build a rustls ClientConfig using only classical (non-PQC) key exchange groups.
/// Explicitly filters out any ML-KEM / PQC groups so we can test classical-only behavior.
fn build_classical_client_config() -> Result<Arc<ClientConfig>> {
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    // Filter out any PQC/ML-KEM key exchange groups
    provider.kx_groups.retain(|g| {
        let name = format!("{:?}", g.name());
        let name_upper = name.to_uppercase();
        !name_upper.contains("MLKEM")
            && !name_upper.contains("ML_KEM")
            && !name_upper.contains("KYBER")
    });
    let config = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| anyhow!("Failed to set TLS versions: {}", e))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerifier))
        .with_no_client_auth();
    Ok(Arc::new(config))
}

/// Build a rustls ClientConfig that offers TLS 1.2 to test for legacy fallback.
fn build_tls12_client_config() -> Result<Arc<ClientConfig>> {
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    provider.kx_groups.retain(|g| {
        let name = format!("{:?}", g.name());
        let name_upper = name.to_uppercase();
        !name_upper.contains("MLKEM")
            && !name_upper.contains("ML_KEM")
            && !name_upper.contains("KYBER")
    });
    let config = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS12])
        .map_err(|e| anyhow!("Failed to set TLS 1.2 version: {}", e))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerifier))
        .with_no_client_auth();
    Ok(Arc::new(config))
}

/// Perform a full TLS handshake with the given config and extract negotiation details.
fn do_handshake(
    tls_config: &Arc<ClientConfig>,
    target: &Target,
    timeout: u64,
) -> HandshakeValidation {
    let server_name = match ServerName::try_from(target.host.as_str()) {
        Ok(name) => name.to_owned(),
        Err(e) => {
            return HandshakeValidation {
                completed: false,
                negotiated_cipher_suite: None,
                negotiated_version: None,
                negotiated_group: None,
                peer_certificate_subject: None,
                peer_certificate_sig_algo: None,
                handshake_error: Some(format!("Invalid server name: {}", e)),
            };
        }
    };

    let mut conn = match ClientConnection::new(tls_config.clone(), server_name) {
        Ok(c) => c,
        Err(e) => {
            return HandshakeValidation {
                completed: false,
                negotiated_cipher_suite: None,
                negotiated_version: None,
                negotiated_group: None,
                peer_certificate_subject: None,
                peer_certificate_sig_algo: None,
                handshake_error: Some(format!("Failed to create TLS connection: {}", e)),
            };
        }
    };

    // Connect TCP synchronously
    let addr_str = format!("{}:{}", target.host, target.port);
    let mut tcp = match TcpStream::connect_timeout(
        &match addr_str.parse() {
            Ok(a) => a,
            Err(_) => {
                // Try DNS resolution
                use std::net::ToSocketAddrs;
                match addr_str.to_socket_addrs() {
                    Ok(mut addrs) => match addrs.next() {
                        Some(a) => a,
                        None => {
                            return HandshakeValidation {
                                completed: false,
                                negotiated_cipher_suite: None,
                                negotiated_version: None,
                                negotiated_group: None,
                                peer_certificate_subject: None,
                                peer_certificate_sig_algo: None,
                                handshake_error: Some(format!(
                                    "Could not resolve {}",
                                    target.host
                                )),
                            };
                        }
                    },
                    Err(e) => {
                        return HandshakeValidation {
                            completed: false,
                            negotiated_cipher_suite: None,
                            negotiated_version: None,
                            negotiated_group: None,
                            peer_certificate_subject: None,
                            peer_certificate_sig_algo: None,
                            handshake_error: Some(format!("DNS resolution failed: {}", e)),
                        };
                    }
                }
            }
        },
        Duration::from_secs(timeout),
    ) {
        Ok(s) => s,
        Err(e) => {
            return HandshakeValidation {
                completed: false,
                negotiated_cipher_suite: None,
                negotiated_version: None,
                negotiated_group: None,
                peer_certificate_subject: None,
                peer_certificate_sig_algo: None,
                handshake_error: Some(format!("TCP connect failed: {}", e)),
            };
        }
    };

    tcp.set_read_timeout(Some(Duration::from_secs(timeout))).ok();
    tcp.set_write_timeout(Some(Duration::from_secs(timeout))).ok();

    // Complete the handshake by doing IO
    let handshake_result = conn.complete_io(&mut tcp);
    if let Err(e) = handshake_result {
        return HandshakeValidation {
            completed: false,
            negotiated_cipher_suite: None,
            negotiated_version: None,
            negotiated_group: None,
            peer_certificate_subject: None,
            peer_certificate_sig_algo: None,
            handshake_error: Some(format!("Handshake failed: {}", e)),
        };
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

    // Extract peer certificate info
    let (cert_subject, cert_sig_algo) = match conn.peer_certificates() {
        Some(certs) if !certs.is_empty() => {
            let cert_der = &certs[0];
            let cert_info = format!("{} bytes", cert_der.len());
            (Some(cert_info), None)
        }
        _ => (None, None),
    };

    HandshakeValidation {
        completed: true,
        negotiated_cipher_suite: cipher_suite,
        negotiated_version: version,
        negotiated_group: group,
        peer_certificate_subject: cert_subject,
        peer_certificate_sig_algo: cert_sig_algo,
        handshake_error: None,
    }
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
    log::info!(
        "Handshake validation: starting full handshake with PQC for {}",
        target
    );

    // Handshake 1: PQC-enabled
    let pqc_config = match build_pqc_client_config() {
        Ok(c) => c,
        Err(e) => {
            let err = HandshakeValidation {
                completed: false,
                negotiated_cipher_suite: None,
                negotiated_version: None,
                negotiated_group: None,
                peer_certificate_subject: None,
                peer_certificate_sig_algo: None,
                handshake_error: Some(format!("Failed to build PQC config: {}", e)),
            };
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

    log::info!(
        "Handshake validation: PQC handshake {} for {} (cipher={}, group={})",
        if pqc_result.completed {
            "completed"
        } else {
            "failed"
        },
        target,
        pqc_result
            .negotiated_cipher_suite
            .as_deref()
            .unwrap_or("none"),
        pqc_result.negotiated_group.as_deref().unwrap_or("none"),
    );

    // Handshake 2: Classical-only
    log::info!(
        "Handshake validation: starting classical-only handshake for {}",
        target
    );

    let classical_config = match build_classical_client_config() {
        Ok(c) => c,
        Err(e) => {
            let err = HandshakeValidation {
                completed: false,
                negotiated_cipher_suite: None,
                negotiated_version: None,
                negotiated_group: None,
                peer_certificate_subject: None,
                peer_certificate_sig_algo: None,
                handshake_error: Some(format!("Failed to build classical config: {}", e)),
            };
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

    log::info!(
        "Handshake validation: classical handshake {} for {} (cipher={}, group={})",
        if classical_result.completed {
            "completed"
        } else {
            "failed"
        },
        target,
        classical_result
            .negotiated_cipher_suite
            .as_deref()
            .unwrap_or("none"),
        classical_result
            .negotiated_group
            .as_deref()
            .unwrap_or("none"),
    );

    // Downgrade analysis
    let pqc_used = pqc_result.completed
        && pqc_result
            .negotiated_group
            .as_ref()
            .map(|g| {
                let g_upper = g.to_uppercase();
                g_upper.contains("MLKEM")
                    || g_upper.contains("ML_KEM")
                    || g_upper.contains("KYBER")
            })
            .unwrap_or(false);

    let classical_works = classical_result.completed;

    // Potential downgrade: server supports PQC (from probe scan) but when we offer
    // PQC + classical, it chose classical instead
    let potential_downgrade = pqc_result.completed
        && !pqc_used
        && classical_works;

    let details = if !pqc_result.completed && !classical_works {
        "Both PQC and classical handshakes failed — server may be unreachable or incompatible"
            .to_string()
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
            "WARNING: Server chose classical group ({}) even though PQC was offered. This may indicate a downgrade or server preference for classical algorithms.",
            pqc_result.negotiated_group.as_deref().unwrap_or("unknown"),
        )
    } else if !pqc_result.completed && classical_works {
        "PQC handshake failed but classical works — server may not support PQC key exchange"
            .to_string()
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
    log::info!(
        "Handshake validation: starting TLS 1.2 fallback probe for {}",
        target
    );

    let tls12_result = match build_tls12_client_config() {
        Ok(c) => {
            let result = do_handshake(&c, target, config.connection_timeout);
            log::info!(
                "Handshake validation: TLS 1.2 probe {} for {} (cipher={}, version={})",
                if result.completed { "completed" } else { "failed" },
                target,
                result.negotiated_cipher_suite.as_deref().unwrap_or("none"),
                result.negotiated_version.as_deref().unwrap_or("none"),
            );
            result
        }
        Err(e) => {
            log::warn!("Handshake validation: could not build TLS 1.2 config: {}", e);
            HandshakeValidation {
                completed: false,
                negotiated_cipher_suite: None,
                negotiated_version: None,
                negotiated_group: None,
                peer_certificate_subject: None,
                peer_certificate_sig_algo: None,
                handshake_error: Some(format!("Failed to build TLS 1.2 config: {}", e)),
            }
        }
    };

    (pqc_result, classical_result, tls12_result, downgrade)
}
