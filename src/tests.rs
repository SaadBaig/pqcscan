#[cfg(test)]
mod tests {
    use crate::handshake::{is_pqc_group, HandshakeValidation, DowngradeCheck};
    use crate::hndl::{self, HndlInput, HndlSeverity};
    use crate::utils::parse_single_target;

    // ── is_pqc_group ──────────────────────────────────────────

    #[test]
    fn is_pqc_group_detects_mlkem() {
        assert!(is_pqc_group("X25519MLKEM768"));
        assert!(is_pqc_group("MLKEM1024"));
        assert!(is_pqc_group("x25519mlkem768"));
    }

    #[test]
    fn is_pqc_group_detects_ml_kem_underscore() {
        assert!(is_pqc_group("ML_KEM_768"));
    }

    #[test]
    fn is_pqc_group_detects_kyber() {
        assert!(is_pqc_group("X25519Kyber768Draft00"));
        assert!(is_pqc_group("SecP256r1Kyber768Draft00"));
    }

    #[test]
    fn is_pqc_group_rejects_classical() {
        assert!(!is_pqc_group("X25519"));
        assert!(!is_pqc_group("secp256r1"));
        assert!(!is_pqc_group("secp384r1"));
        assert!(!is_pqc_group("ffdhe2048"));
        assert!(!is_pqc_group(""));
    }

    // ── parse_single_target ───────────────────────────────────

    #[test]
    fn parse_target_with_port() {
        let t = parse_single_target(&"example.com:443".to_string(), None).unwrap();
        assert_eq!(t.host, "example.com");
        assert_eq!(t.port, 443);
    }

    #[test]
    fn parse_target_with_default_port() {
        let t = parse_single_target(&"example.com".to_string(), Some(22)).unwrap();
        assert_eq!(t.host, "example.com");
        assert_eq!(t.port, 22);
    }

    #[test]
    fn parse_target_no_port_no_default_fails() {
        assert!(parse_single_target(&"example.com".to_string(), None).is_err());
    }

    #[test]
    fn parse_target_invalid_port_fails() {
        assert!(parse_single_target(&"example.com:notaport".to_string(), None).is_err());
    }

    // ── Risk assessment helpers ─────────────────────────────

    fn make_completed_handshake(group: &str, cipher: &str, version: &str) -> HandshakeValidation {
        HandshakeValidation {
            completed: true,
            negotiated_cipher_suite: Some(cipher.to_string()),
            negotiated_version: Some(version.to_string()),
            negotiated_group: Some(group.to_string()),
            peer_certificate_subject: None,
            peer_certificate_sig_algo: None,
            peer_certificate_key_type: None,
            peer_certificate_key_bits: None,
            peer_certificate_validity_days: None,
            session_tickets_received: None,
            handshake_error: None,
        }
    }

    fn make_failed_handshake() -> HandshakeValidation {
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
            handshake_error: Some("test error".to_string()),
        }
    }

    fn make_downgrade(potential: bool) -> DowngradeCheck {
        DowngradeCheck {
            pqc_offered_and_used: !potential,
            classical_fallback_works: true,
            potential_downgrade: potential,
            details: "test".to_string(),
        }
    }

    // ── TLS Risk: No PQC = CRITICAL ──────────────────────────

    #[test]
    fn risk_no_pqc_is_critical() {
        let pqc_hs = make_completed_handshake("X25519", "TLS13_AES_256_GCM_SHA384", "TLSv1_3");
        let classical_hs = make_completed_handshake("X25519", "TLS13_AES_256_GCM_SHA384", "TLSv1_3");
        let tls12_hs = make_failed_handshake();
        let dc = make_downgrade(false);
        let input = HndlInput {
            pqc_supported: false, handshake_pqc: Some(&pqc_hs),
            handshake_classical: Some(&classical_hs), handshake_tls12: Some(&tls12_hs),
            downgrade_check: Some(&dc), cert_key_type: None, cert_key_bits: None, cert_validity_days: None,
        };
        let result = hndl::assess_hndl_risk(&input);
        assert_eq!(result.risk_level, HndlSeverity::Critical);
        assert!(result.quantum_vulnerable);
    }

    // ── TLS Risk: Static RSA = CRITICAL ──────────────────────

    #[test]
    fn risk_static_rsa_is_critical() {
        let pqc_hs = make_failed_handshake();
        let classical_hs = make_completed_handshake("", "TLS_RSA_WITH_AES_128_GCM_SHA256", "TLSv1_2");
        let tls12_hs = make_completed_handshake("", "TLS_RSA_WITH_AES_128_GCM_SHA256", "TLSv1_2");
        let dc = make_downgrade(false);
        let input = HndlInput {
            pqc_supported: false, handshake_pqc: Some(&pqc_hs),
            handshake_classical: Some(&classical_hs), handshake_tls12: Some(&tls12_hs),
            downgrade_check: Some(&dc), cert_key_type: None, cert_key_bits: None, cert_validity_days: None,
        };
        let result = hndl::assess_hndl_risk(&input);
        assert_eq!(result.risk_level, HndlSeverity::Critical);
    }

    // ── TLS Risk: PQC + TLS 1.2 = MEDIUM ────────────────────

    #[test]
    fn risk_pqc_with_tls12_is_medium() {
        let pqc_hs = make_completed_handshake("X25519MLKEM768", "TLS13_AES_256_GCM_SHA384", "TLSv1_3");
        let classical_hs = make_completed_handshake("X25519", "TLS13_AES_256_GCM_SHA384", "TLSv1_3");
        let tls12_hs = make_completed_handshake("", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "TLSv1_2");
        let dc = make_downgrade(false);
        let input = HndlInput {
            pqc_supported: true, handshake_pqc: Some(&pqc_hs),
            handshake_classical: Some(&classical_hs), handshake_tls12: Some(&tls12_hs),
            downgrade_check: Some(&dc), cert_key_type: None, cert_key_bits: None, cert_validity_days: None,
        };
        let result = hndl::assess_hndl_risk(&input);
        assert_eq!(result.risk_level, HndlSeverity::Medium);
        assert!(!result.quantum_vulnerable);
    }

    // ── TLS Risk: PQC advertised but not negotiated = HIGH ───

    #[test]
    fn risk_pqc_not_negotiated_is_high() {
        let pqc_hs = make_completed_handshake("X25519", "TLS13_AES_256_GCM_SHA384", "TLSv1_3");
        let classical_hs = make_completed_handshake("X25519", "TLS13_AES_256_GCM_SHA384", "TLSv1_3");
        let tls12_hs = make_failed_handshake();
        let dc = make_downgrade(false);
        let input = HndlInput {
            pqc_supported: true, handshake_pqc: Some(&pqc_hs),
            handshake_classical: Some(&classical_hs), handshake_tls12: Some(&tls12_hs),
            downgrade_check: Some(&dc), cert_key_type: None, cert_key_bits: None, cert_validity_days: None,
        };
        let result = hndl::assess_hndl_risk(&input);
        assert_eq!(result.risk_level, HndlSeverity::High);
        assert!(result.findings.iter().any(|f| f.category == "PQC Advertised But Not Negotiated"));
    }

    // ── TLS Risk: Downgrade = HIGH ───────────────────────────

    #[test]
    fn risk_downgrade_is_high() {
        let pqc_hs = make_completed_handshake("X25519MLKEM768", "TLS13_AES_256_GCM_SHA384", "TLSv1_3");
        let classical_hs = make_completed_handshake("X25519", "TLS13_AES_256_GCM_SHA384", "TLSv1_3");
        let tls12_hs = make_failed_handshake();
        let dc = make_downgrade(true);
        let input = HndlInput {
            pqc_supported: true, handshake_pqc: Some(&pqc_hs),
            handshake_classical: Some(&classical_hs), handshake_tls12: Some(&tls12_hs),
            downgrade_check: Some(&dc), cert_key_type: None, cert_key_bits: None, cert_validity_days: None,
        };
        let result = hndl::assess_hndl_risk(&input);
        assert_eq!(result.risk_level, HndlSeverity::High);
        assert!(result.findings.iter().any(|f| f.category == "Downgrade Amplifies Risk"));
    }

    // ── TLS Risk: ECDSA cert = MEDIUM ────────────────────────

    #[test]
    fn risk_ecdsa_cert_is_medium() {
        let pqc_hs = make_completed_handshake("X25519MLKEM768", "TLS13_AES_256_GCM_SHA384", "TLSv1_3");
        let classical_hs = make_completed_handshake("X25519", "TLS13_AES_256_GCM_SHA384", "TLSv1_3");
        let tls12_hs = make_failed_handshake();
        let dc = make_downgrade(false);
        let input = HndlInput {
            pqc_supported: true, handshake_pqc: Some(&pqc_hs),
            handshake_classical: Some(&classical_hs), handshake_tls12: Some(&tls12_hs),
            downgrade_check: Some(&dc), cert_key_type: Some("ECDSA-P-256"),
            cert_key_bits: Some(256), cert_validity_days: Some(90),
        };
        let result = hndl::assess_hndl_risk(&input);
        assert!(result.findings.iter().any(|f| f.category == "ECDSA Certificate" && f.severity == HndlSeverity::Medium));
    }

    // ── TLS Risk: PQC cert = INFO ────────────────────────────

    #[test]
    fn risk_pqc_cert_is_info() {
        let pqc_hs = make_completed_handshake("X25519MLKEM768", "TLS13_AES_256_GCM_SHA384", "TLSv1_3");
        let classical_hs = make_completed_handshake("X25519", "TLS13_AES_256_GCM_SHA384", "TLSv1_3");
        let tls12_hs = make_failed_handshake();
        let dc = make_downgrade(false);
        let input = HndlInput {
            pqc_supported: true, handshake_pqc: Some(&pqc_hs),
            handshake_classical: Some(&classical_hs), handshake_tls12: Some(&tls12_hs),
            downgrade_check: Some(&dc), cert_key_type: Some("ML-DSA-65"),
            cert_key_bits: None, cert_validity_days: Some(90),
        };
        let result = hndl::assess_hndl_risk(&input);
        assert!(result.findings.iter().any(|f| f.category == "PQC Certificate" && f.severity == HndlSeverity::Info));
        assert!(!result.findings.iter().any(|f| f.category.contains("RSA") || f.category.contains("ECDSA")));
    }

    // ── TLS Risk: Deprecated Kyber = MEDIUM ──────────────────

    #[test]
    fn risk_deprecated_kyber_is_medium() {
        let pqc_hs = make_completed_handshake("X25519Kyber768Draft00", "TLS13_AES_256_GCM_SHA384", "TLSv1_3");
        let classical_hs = make_completed_handshake("X25519", "TLS13_AES_256_GCM_SHA384", "TLSv1_3");
        let tls12_hs = make_failed_handshake();
        let dc = make_downgrade(false);
        let input = HndlInput {
            pqc_supported: true, handshake_pqc: Some(&pqc_hs),
            handshake_classical: Some(&classical_hs), handshake_tls12: Some(&tls12_hs),
            downgrade_check: Some(&dc), cert_key_type: None, cert_key_bits: None, cert_validity_days: None,
        };
        let result = hndl::assess_hndl_risk(&input);
        assert!(result.findings.iter().any(|f| f.category == "Deprecated PQC Algorithm"));
    }

    // ── TLS Risk: RSA-2048 without PQC = HIGH ────────────────

    #[test]
    fn risk_rsa2048_no_pqc_is_high() {
        let pqc_hs = make_failed_handshake();
        let classical_hs = make_completed_handshake("X25519", "TLS13_AES_256_GCM_SHA384", "TLSv1_3");
        let tls12_hs = make_failed_handshake();
        let dc = make_downgrade(false);
        let input = HndlInput {
            pqc_supported: false, handshake_pqc: Some(&pqc_hs),
            handshake_classical: Some(&classical_hs), handshake_tls12: Some(&tls12_hs),
            downgrade_check: Some(&dc), cert_key_type: Some("RSA"),
            cert_key_bits: Some(2048), cert_validity_days: Some(90),
        };
        let result = hndl::assess_hndl_risk(&input);
        assert!(result.findings.iter().any(|f| f.category == "RSA-2048 Certificate" && f.severity == HndlSeverity::High));
    }

    // ── TLS Risk: RSA-2048 with PQC = capped MEDIUM ──────────

    #[test]
    fn risk_rsa2048_with_pqc_capped() {
        let pqc_hs = make_completed_handshake("X25519MLKEM768", "TLS13_AES_256_GCM_SHA384", "TLSv1_3");
        let classical_hs = make_completed_handshake("X25519", "TLS13_AES_256_GCM_SHA384", "TLSv1_3");
        let tls12_hs = make_failed_handshake();
        let dc = make_downgrade(false);
        let input = HndlInput {
            pqc_supported: true, handshake_pqc: Some(&pqc_hs),
            handshake_classical: Some(&classical_hs), handshake_tls12: Some(&tls12_hs),
            downgrade_check: Some(&dc), cert_key_type: Some("RSA"),
            cert_key_bits: Some(2048), cert_validity_days: Some(90),
        };
        let result = hndl::assess_hndl_risk(&input);
        assert!(result.findings.iter().any(|f| f.category.contains("RSA") && f.severity == HndlSeverity::Medium));
    }

    // ── TLS Risk: FFDHE = HIGH ───────────────────────────────

    #[test]
    fn risk_ffdhe_is_high() {
        let pqc_hs = make_completed_handshake("X25519MLKEM768", "TLS13_AES_256_GCM_SHA384", "TLSv1_3");
        let classical_hs = make_completed_handshake("ffdhe2048", "TLS13_AES_256_GCM_SHA384", "TLSv1_3");
        let tls12_hs = make_failed_handshake();
        let dc = make_downgrade(false);
        let input = HndlInput {
            pqc_supported: true, handshake_pqc: Some(&pqc_hs),
            handshake_classical: Some(&classical_hs), handshake_tls12: Some(&tls12_hs),
            downgrade_check: Some(&dc), cert_key_type: None, cert_key_bits: None, cert_validity_days: None,
        };
        let result = hndl::assess_hndl_risk(&input);
        assert!(result.findings.iter().any(|f| f.category == "Finite Field DH Key Exchange" && f.severity == HndlSeverity::High));
    }

    // ── TLS Risk: Long-lived cert ────────────────────────────

    #[test]
    fn risk_long_lived_cert() {
        let pqc_hs = make_completed_handshake("X25519MLKEM768", "TLS13_AES_256_GCM_SHA384", "TLSv1_3");
        let classical_hs = make_completed_handshake("X25519", "TLS13_AES_256_GCM_SHA384", "TLSv1_3");
        let tls12_hs = make_failed_handshake();
        let dc = make_downgrade(false);
        let input = HndlInput {
            pqc_supported: true, handshake_pqc: Some(&pqc_hs),
            handshake_classical: Some(&classical_hs), handshake_tls12: Some(&tls12_hs),
            downgrade_check: Some(&dc), cert_key_type: Some("RSA"),
            cert_key_bits: Some(4096), cert_validity_days: Some(730),
        };
        let result = hndl::assess_hndl_risk(&input);
        assert!(result.findings.iter().any(|f| f.category == "Long-Lived Certificate"));
    }

    // ── SSH Risk ─────────────────────────────────────────────

    #[test]
    fn ssh_no_pqc_is_critical() {
        let r = hndl::assess_ssh_hndl_risk(false, &[], &["curve25519-sha256".to_string()]);
        assert_eq!(r.risk_level, HndlSeverity::Critical);
        assert!(r.quantum_vulnerable);
    }

    #[test]
    fn ssh_pqc_with_weak_kex_is_high() {
        let r = hndl::assess_ssh_hndl_risk(
            true,
            &["sntrup761x25519-sha512".to_string()],
            &["curve25519-sha256".to_string(), "diffie-hellman-group14-sha256".to_string()],
        );
        assert_eq!(r.risk_level, HndlSeverity::High);
        assert!(r.findings.iter().any(|f| f.category == "Weak Classical KEX Available"));
    }

    #[test]
    fn ssh_pqc_with_normal_kex_is_medium() {
        let r = hndl::assess_ssh_hndl_risk(
            true,
            &["sntrup761x25519-sha512".to_string()],
            &["curve25519-sha256".to_string()],
        );
        assert_eq!(r.risk_level, HndlSeverity::Medium);
    }

    #[test]
    fn ssh_pqc_only_is_info() {
        let r = hndl::assess_ssh_hndl_risk(true, &["sntrup761x25519-sha512".to_string()], &[]);
        assert_eq!(r.risk_level, HndlSeverity::Info);
        assert!(!r.quantum_vulnerable);
    }
}
