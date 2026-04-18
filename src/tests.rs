#[cfg(test)]
mod tests {
    use crate::handshake::{is_pqc_group, HandshakeValidation, DowngradeCheck};
    use crate::hndl::{self, HndlInput, HndlSeverity};
    use crate::utils::parse_single_target;

    // ── wrap_text ──────────────────────────────────────────────

    use crate::wrap_text;

    #[test]
    fn wrap_text_short_line_unchanged() {
        let result = wrap_text("hello world", 80);
        assert_eq!(result, vec!["hello world"]);
    }

    #[test]
    fn wrap_text_wraps_at_boundary() {
        let result = wrap_text("aaa bbb ccc ddd", 7);
        assert_eq!(result, vec!["aaa bbb", "ccc ddd"]);
    }

    #[test]
    fn wrap_text_empty_input() {
        let result = wrap_text("", 80);
        assert!(result.is_empty());
    }

    #[test]
    fn wrap_text_single_long_word() {
        let result = wrap_text("superlongword", 5);
        assert_eq!(result, vec!["superlongword"]);
    }

    // ── is_pqc_group ──────────────────────────────────────────

    #[test]
    fn is_pqc_group_detects_mlkem() {
        assert!(is_pqc_group("X25519MLKEM768"));
        assert!(is_pqc_group("MLKEM1024"));
        assert!(is_pqc_group("x25519mlkem768"));
    }

    #[test]
    fn is_pqc_group_detects_kyber() {
        assert!(is_pqc_group("X25519Kyber768Draft00"));
    }

    #[test]
    fn is_pqc_group_rejects_classical() {
        assert!(!is_pqc_group("X25519"));
        assert!(!is_pqc_group("secp256r1"));
        assert!(!is_pqc_group("secp384r1"));
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
        let result = parse_single_target(&"example.com".to_string(), None);
        assert!(result.is_err());
    }

    #[test]
    fn parse_target_invalid_port_fails() {
        let result = parse_single_target(&"example.com:notaport".to_string(), None);
        assert!(result.is_err());
    }

    // ── HNDL assessment ─────────────────────────────────────

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

    #[test]
    fn hndl_no_pqc_is_critical() {
        let pqc_hs = make_completed_handshake("X25519", "TLS13_AES_256_GCM_SHA384", "TLSv1_3");
        let classical_hs = make_completed_handshake("X25519", "TLS13_AES_256_GCM_SHA384", "TLSv1_3");
        let tls12_hs = make_failed_handshake();
        let downgrade = DowngradeCheck {
            pqc_offered_and_used: false,
            classical_fallback_works: true,
            potential_downgrade: true,
            details: "test".to_string(),
        };

        let input = HndlInput {
            pqc_supported: false,
            handshake_pqc: Some(&pqc_hs),
            handshake_classical: Some(&classical_hs),
            handshake_tls12: Some(&tls12_hs),
            downgrade_check: Some(&downgrade),
            cert_key_type: None,
            cert_key_bits: None,
            cert_validity_days: None,
        };

        let result = hndl::assess_hndl_risk(&input);
        assert_eq!(result.risk_level, HndlSeverity::Critical);
        assert!(result.quantum_vulnerable);
        assert!(result.findings.iter().any(|f| f.category == "No PQC Key Exchange"));
    }

    #[test]
    fn hndl_pqc_active_with_tls12_fallback_is_high() {
        let pqc_hs = make_completed_handshake("X25519MLKEM768", "TLS13_AES_256_GCM_SHA384", "TLSv1_3");
        let classical_hs = make_completed_handshake("X25519", "TLS13_AES_256_GCM_SHA384", "TLSv1_3");
        let tls12_hs = make_completed_handshake("", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "TLSv1_2");
        let downgrade = DowngradeCheck {
            pqc_offered_and_used: true,
            classical_fallback_works: true,
            potential_downgrade: false,
            details: "test".to_string(),
        };

        let input = HndlInput {
            pqc_supported: true,
            handshake_pqc: Some(&pqc_hs),
            handshake_classical: Some(&classical_hs),
            handshake_tls12: Some(&tls12_hs),
            downgrade_check: Some(&downgrade),
            cert_key_type: None,
            cert_key_bits: None,
            cert_validity_days: None,
        };

        let result = hndl::assess_hndl_risk(&input);
        assert_eq!(result.risk_level, HndlSeverity::High);
        assert!(result.findings.iter().any(|f| f.category == "TLS 1.2 Fallback Available"));
    }

    #[test]
    fn hndl_pqc_active_no_tls12_is_medium_or_lower() {
        let pqc_hs = make_completed_handshake("X25519MLKEM768", "TLS13_AES_256_GCM_SHA384", "TLSv1_3");
        let classical_hs = make_completed_handshake("X25519", "TLS13_AES_256_GCM_SHA384", "TLSv1_3");
        let tls12_hs = make_failed_handshake();
        let downgrade = DowngradeCheck {
            pqc_offered_and_used: true,
            classical_fallback_works: true,
            potential_downgrade: false,
            details: "test".to_string(),
        };

        let input = HndlInput {
            pqc_supported: true,
            handshake_pqc: Some(&pqc_hs),
            handshake_classical: Some(&classical_hs),
            handshake_tls12: Some(&tls12_hs),
            downgrade_check: Some(&downgrade),
            cert_key_type: None,
            cert_key_bits: None,
            cert_validity_days: None,
        };

        let result = hndl::assess_hndl_risk(&input);
        assert!(result.risk_level <= HndlSeverity::Medium);
        assert!(!result.quantum_vulnerable);
    }

    #[test]
    fn hndl_long_lived_cert_flagged() {
        let pqc_hs = make_completed_handshake("X25519MLKEM768", "TLS13_AES_256_GCM_SHA384", "TLSv1_3");
        let classical_hs = make_completed_handshake("X25519", "TLS13_AES_256_GCM_SHA384", "TLSv1_3");
        let tls12_hs = make_failed_handshake();
        let downgrade = DowngradeCheck {
            pqc_offered_and_used: true,
            classical_fallback_works: true,
            potential_downgrade: false,
            details: "test".to_string(),
        };

        let input = HndlInput {
            pqc_supported: true,
            handshake_pqc: Some(&pqc_hs),
            handshake_classical: Some(&classical_hs),
            handshake_tls12: Some(&tls12_hs),
            downgrade_check: Some(&downgrade),
            cert_key_type: Some("RSA"),
            cert_key_bits: Some(2048),
            cert_validity_days: Some(730),
        };

        let result = hndl::assess_hndl_risk(&input);
        assert!(result.findings.iter().any(|f| f.category == "Long-Lived Certificate"));
        assert!(result.findings.iter().any(|f| f.category == "RSA-2048 Certificate"));
    }

    #[test]
    fn hndl_rsa_2048_cert_is_high() {
        let pqc_hs = make_completed_handshake("X25519MLKEM768", "TLS13_AES_256_GCM_SHA384", "TLSv1_3");
        let classical_hs = make_completed_handshake("X25519", "TLS13_AES_256_GCM_SHA384", "TLSv1_3");
        let tls12_hs = make_failed_handshake();
        let downgrade = DowngradeCheck {
            pqc_offered_and_used: true,
            classical_fallback_works: true,
            potential_downgrade: false,
            details: "test".to_string(),
        };

        let input = HndlInput {
            pqc_supported: true,
            handshake_pqc: Some(&pqc_hs),
            handshake_classical: Some(&classical_hs),
            handshake_tls12: Some(&tls12_hs),
            downgrade_check: Some(&downgrade),
            cert_key_type: Some("RSA"),
            cert_key_bits: Some(2048),
            cert_validity_days: Some(90),
        };

        let result = hndl::assess_hndl_risk(&input);
        assert!(result.findings.iter().any(|f| f.severity == HndlSeverity::High && f.category.contains("RSA")));
    }
}
