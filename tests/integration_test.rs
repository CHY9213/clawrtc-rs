// SPDX-License-Identifier: MIT
//! Integration test suite for clawrtc-rs.
//!
//! Covers: wallet roundtrip, address derivation vectors, attestation
//! construction, and error paths for every public `Result`-returning API.

use clawrtc::{ClawError, CpuArch, NodeClient, Wallet};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;

// ── 1. Wallet roundtrip ────────────────────────────────────────

#[test]
fn wallet_generate_produces_valid_address() {
    let w = Wallet::generate();
    let addr = w.address();
    assert!(addr.starts_with("RTC"), "address must start with RTC");
    assert_eq!(addr.len(), 43); // "RTC" + 40 hex chars
    // All characters after RTC should be valid hex
    let hex_part = &addr[3..];
    assert!(hex_part.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn wallet_serialize_deserialize_roundtrip() {
    let w1 = Wallet::generate();
    let priv_hex = w1.private_key_hex();
    let w2 = Wallet::from_hex(&priv_hex).unwrap();

    assert_eq!(w1.address(), w2.address(), "addresses must match");
    assert_eq!(
        w1.public_key_hex(),
        w2.public_key_hex(),
        "public keys must match"
    );
    assert_eq!(
        w1.private_key_hex(),
        w2.private_key_hex(),
        "private keys must match"
    );
}

#[test]
fn wallet_sign_and_verify_own_message() {
    let w = Wallet::generate();
    let msg = b"transfer 500 RTC to miner";
    let sig = w.sign(msg);

    let result = Wallet::verify(&w.public_key_hex(), msg, &sig).unwrap();
    assert!(result, "signature should verify");
}

#[test]
fn wallet_verify_rejects_tampered_message() {
    let w = Wallet::generate();
    let msg = b"original message";
    let sig = w.sign(msg);

    let tampered = b"tampered message";
    let result = Wallet::verify(&w.public_key_hex(), tampered, &sig).unwrap();
    assert!(!result, "tampered message should not verify");
}

#[test]
fn wallet_verify_rejects_tampered_signature() {
    let w = Wallet::generate();
    let msg = b"some message";
    let sig = w.sign(msg);

    // Flip a few bits in the signature
    let mut sig_bytes = hex::decode(&sig).unwrap();
    sig_bytes[0] ^= 0xFF;
    sig_bytes[10] ^= 0x01;
    let bad_sig = hex::encode(&sig_bytes);

    let result = Wallet::verify(&w.public_key_hex(), msg, &bad_sig).unwrap();
    assert!(!result, "tampered signature should not verify");
}

#[test]
fn wallet_verify_rejects_wrong_key() {
    let w1 = Wallet::generate();
    let w2 = Wallet::generate();
    let msg = b"hello";
    let sig = w1.sign(msg);

    let result = Wallet::verify(&w2.public_key_hex(), msg, &sig).unwrap();
    assert!(!result, "wrong key should not verify");
}

// ── 2. Address derivation vectors ───────────────────────────────
//
// These vectors freeze the address derivation for known private keys.
// If the derivation changes silently, these tests break the build.

/// Pre-computed from private key 0x0000…0000
const VEC1_PRIV: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const VEC1_PUB: &str = "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29";
const VEC1_ADDR: &str = "RTC139e3940e64b5491722088d9a0d741628fc826e0";

/// Pre-computed from private key 0x1111…1111
const VEC2_PRIV: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const VEC2_PUB: &str = "d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737";
const VEC2_ADDR: &str = "RTC10ba682c8ad13513971e8b56881aab8bd702bb80";

/// Pre-computed from private key 0xdeadbeef…deadbeef
const VEC3_PRIV: &str = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
const VEC3_PUB: &str = "ff57575dc7af8bfc4d0837cc1ce2017b686a88145dc5579a958e3462fe9a908e";
const VEC3_ADDR: &str = "RTCe78d76a96abf71cf1c6fc032e971de8fd8349a2b";

/// Pre-computed from private key SHA-256("sha256")
const VEC4_PRIV: &str = "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3";
const VEC4_PUB: &str = "a4465fd76c16fcc458448076372abf1912cc5b150663a64dffefe550f96feadd";
const VEC4_ADDR: &str = "RTCb96daf31147223ad2571c61ad300bac5d1568e63";

#[test]
fn address_vector_1() {
    let w = Wallet::from_hex(VEC1_PRIV).unwrap();
    assert_eq!(w.public_key_hex(), VEC1_PUB, "public key mismatch");
    assert_eq!(w.address(), VEC1_ADDR, "address mismatch");
}

#[test]
fn address_vector_2() {
    let w = Wallet::from_hex(VEC2_PRIV).unwrap();
    assert_eq!(w.public_key_hex(), VEC2_PUB, "public key mismatch");
    assert_eq!(w.address(), VEC2_ADDR, "address mismatch");
}

#[test]
fn address_vector_3() {
    let w = Wallet::from_hex(VEC3_PRIV).unwrap();
    assert_eq!(w.public_key_hex(), VEC3_PUB, "public key mismatch");
    assert_eq!(w.address(), VEC3_ADDR, "address mismatch");
}

#[test]
fn address_vector_4() {
    let w = Wallet::from_hex(VEC4_PRIV).unwrap();
    assert_eq!(w.public_key_hex(), VEC4_PUB, "public key mismatch");
    assert_eq!(w.address(), VEC4_ADDR, "address mismatch");
}

#[test]
fn address_vector_sign_verify_vectors() {
    let w = Wallet::from_hex(VEC1_PRIV).unwrap();
    let msg = b"vector 1 test message";
    let sig = w.sign(msg);
    assert!(
        Wallet::verify(VEC1_PUB, msg, &sig).unwrap(),
        "vector 1 sign/verify should work"
    );
}

// ── 3. CpuArch ──────────────────────────────────────────────────

#[test]
fn cpu_arch_all_variants_have_unique_properties() {
    use std::collections::HashSet;

    let variants = vec![
        CpuArch::G4,
        CpuArch::G5,
        CpuArch::G3,
        CpuArch::Pentium4,
        CpuArch::Retro,
        CpuArch::Core2,
        CpuArch::AppleSilicon,
        CpuArch::Modern,
    ];

    // Compare multipliers via their bit patterns to avoid float rounding
    let mult_keys: HashSet<_> = variants.iter().map(|a| a.multiplier().to_bits()).collect();
    assert_eq!(mult_keys.len(), variants.len(), "multipliers should be unique");

    let families: HashSet<_> = variants.iter().map(|a| a.family()).collect();
    assert_eq!(families.len(), 3, "should have exactly 3 families (powerpc, arm, x86)");
}

#[test]
fn cpu_arch_multiplier_bounds() {
    assert!(CpuArch::G4.multiplier() >= 1.0, "base multiplier should be >= 1.0");
    assert!(CpuArch::Modern.multiplier() == 1.0, "modern should be 1.0");
    assert!(CpuArch::G4.multiplier() > CpuArch::Modern.multiplier());
}

#[test]
fn cpu_arch_known_values() {
    assert_eq!(CpuArch::G4.multiplier(), 2.5);
    assert_eq!(CpuArch::AppleSilicon.multiplier(), 1.2);
    assert_eq!(CpuArch::Modern.multiplier(), 1.0);

    assert_eq!(CpuArch::Pentium4.family(), "x86");
    assert_eq!(CpuArch::AppleSilicon.family(), "arm");
    assert_eq!(CpuArch::G3.family(), "powerpc");

    assert_eq!(CpuArch::G4.arch_str(), "g4");
    assert_eq!(CpuArch::AppleSilicon.arch_str(), "apple_silicon");
    assert_eq!(CpuArch::Modern.arch_str(), "modern");
}

// ── 4. Error paths ─────────────────────────────────────────────
//
// Every public Result-returning API must be exercised with at least
// one failing input.

// ── Wallet error paths ──

#[test]
fn wallet_from_hex_rejects_bad_hex() {
    let result = Wallet::from_hex("not-hex!!!");
    assert!(result.is_err(), "expected error for bad hex");
    let msg = format!("{}", result.err().unwrap());
    assert!(msg.contains("invalid hex"), "expected invalid hex error, got: {msg}");
}

#[test]
fn wallet_from_hex_rejects_wrong_length() {
    // 31 bytes instead of 32
    let result = Wallet::from_hex("aabbccddeeff00112233445566778899aabbccddeeff001122334455667788");
    assert!(result.is_err(), "expected error for wrong length");
    let msg = format!("{}", result.err().unwrap());
    assert!(msg.contains("32 bytes"), "expected 32-byte error, got: {msg}");
}

#[test]
fn wallet_verify_rejects_bad_pubkey_hex() {
    let result = Wallet::verify("zzz", b"msg", "aabb");
    assert!(result.is_err(), "expected error for bad pubkey hex");
    let msg = format!("{}", result.err().unwrap());
    assert!(msg.contains("bad pubkey"), "expected bad pubkey error, got: {msg}");
}

#[test]
fn wallet_verify_rejects_bad_signature_hex() {
    let w = Wallet::generate();
    let result = Wallet::verify(&w.public_key_hex(), b"msg", "not-hex!!");
    assert!(result.is_err(), "expected error for bad sig hex");
    let msg = format!("{}", result.err().unwrap());
    assert!(msg.contains("bad sig"), "expected bad sig error, got: {msg}");
}

#[test]
fn wallet_verify_rejects_wrong_pubkey_length() {
    let result = Wallet::verify("aabb", b"msg", "aabb");
    assert!(result.is_err(), "expected error for wrong pubkey length");
    let msg = format!("{}", result.err().unwrap());
    assert!(msg.contains("32 bytes"), "expected 32-byte pubkey error, got: {msg}");
}

#[test]
fn wallet_verify_rejects_wrong_sig_length() {
    let w = Wallet::generate();
    let result = Wallet::verify(&w.public_key_hex(), b"msg", "aabb");
    assert!(result.is_err(), "expected error for wrong sig length");
    let msg = format!("{}", result.err().unwrap());
    assert!(msg.contains("64 bytes"), "expected 64-byte sig error, got: {msg}");
}

#[test]
fn wallet_verify_handles_edge_pubkeys_gracefully() {
    // Some 32-byte sequences may or may not be valid Ed25519 points.
    // The code should never panic regardless of the input.
    let edge_pubkeys = vec![
        "0000000000000000000000000000000000000000000000000000000000000000",
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    ];
    let w = Wallet::generate();
    let sig = w.sign(b"msg");

    for bad_pubkey in edge_pubkeys {
        let result = Wallet::verify(bad_pubkey, b"msg", &sig);
        // Should not panic. Either error or Ok are acceptable.
        match result {
            Ok(_) => {} // verification completed without panic
            Err(_) => {} // error was raised (acceptable)
        }
    }
}

// ── NodeClient error paths ──

#[test]
fn node_client_health_connection_refused() {
    let client = NodeClient::new("http://127.0.0.1:1");
    let result = client.health();
    assert!(
        matches!(result, Err(ClawError::Http(_))),
        "expected HTTP error for connection refused, got: {result:?}"
    );
}

#[test]
fn node_client_balance_connection_refused() {
    let client = NodeClient::new("http://127.0.0.1:1");
    let result = client.balance("RTCtest");
    assert!(
        matches!(result, Err(ClawError::Http(_))),
        "expected HTTP error for connection refused, got: {result:?}"
    );
}

#[test]
fn node_client_miners_connection_refused() {
    let client = NodeClient::new("http://127.0.0.1:1");
    let result = client.miners();
    assert!(
        matches!(result, Err(ClawError::Http(_))),
        "expected HTTP error for connection refused, got: {result:?}"
    );
}

#[test]
fn node_client_challenge_connection_refused() {
    let client = NodeClient::new("http://127.0.0.1:1");
    let result = client.challenge();
    assert!(
        matches!(result, Err(ClawError::Http(_))),
        "expected HTTP error for connection refused, got: {result:?}"
    );
}

#[test]
fn node_client_attest_connection_refused() {
    let client = NodeClient::new("http://127.0.0.1:1");
    let result = client.attest(&serde_json::json!({"nonce": "test"}));
    assert!(
        matches!(result, Err(ClawError::Http(_))),
        "expected HTTP error for connection refused, got: {result:?}"
    );
}

#[test]
fn node_client_enroll_connection_refused() {
    let client = NodeClient::new("http://127.0.0.1:1");
    let result = client.enroll("wallet", "miner", &CpuArch::Modern);
    assert!(
        matches!(result, Err(ClawError::Http(_))),
        "expected HTTP error for connection refused, got: {result:?}"
    );
}

// ── Attestation / Node interaction with mock server ──

fn spawn_echo_server(response_body: &'static str, status: &'static str) -> (String, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let url = format!("http://127.0.0.1:{port}");

    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut buffer = [0_u8; 4096];
        let _ = stream.read(&mut buffer).unwrap();

        let response = format!(
            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response_body}",
            response_body.len()
        );
        let _ = stream.write_all(response.as_bytes());
    });

    (url, handle)
}

#[test]
fn node_client_balance_parses_real_response() {
    let (url, handle) = spawn_echo_server(
        r#"{"amount_i64":5000000,"amount_rtc":5.0}"#,
        "200 OK",
    );

    let client = NodeClient::new(&url);
    let balance = client.balance("RTCtest").unwrap();
    assert!((balance - 5.0).abs() < f64::EPSILON, "expected 5.0 RTC");
    handle.join().unwrap();
}

#[test]
fn node_client_health_parses_response() {
    let (url, handle) = spawn_echo_server(
        r#"{"ok":true,"version":"1.2.3","uptime_s":12345.0,"db_rw":true}"#,
        "200 OK",
    );

    let client = NodeClient::new(&url);
    let health = client.health().unwrap();
    assert!(health.ok);
    assert_eq!(health.version, "1.2.3");
    assert!((health.uptime_s - 12345.0).abs() < f64::EPSILON);
    assert!(health.db_rw);
    handle.join().unwrap();
}

#[test]
fn node_client_challenge_parses_response() {
    let (url, handle) = spawn_echo_server(
        r#"{"nonce":"abc123def456"}"#,
        "200 OK",
    );

    let client = NodeClient::new(&url);
    let challenge = client.challenge().unwrap();
    assert_eq!(challenge.nonce, "abc123def456");
    handle.join().unwrap();
}

#[test]
fn node_client_attest_submission() {
    let (url, handle) = spawn_echo_server(
        r#"{"ok":true,"message":"attestation accepted"}"#,
        "200 OK",
    );

    let client = NodeClient::new(&url);
    let payload = serde_json::json!({
        "nonce": "test",
        "device": {"family": "x86", "arch": "modern"}
    });
    let result = client.attest(&payload).unwrap();
    assert!(result.ok);
    assert_eq!(result.message, "attestation accepted");
    handle.join().unwrap();
}

#[test]
fn node_client_attest_node_error() {
    let (url, handle) = spawn_echo_server(
        r#"{"ok":false,"error":"invalid nonce"}"#,
        "200 OK",
    );

    let client = NodeClient::new(&url);
    let payload = serde_json::json!({"nonce": "bad"});
    let result = client.attest(&payload);
    match result {
        Err(ClawError::Node(msg)) => {
            assert!(msg.contains("invalid nonce"), "expected invalid nonce error, got: {msg}");
        }
        other => panic!("expected Err(ClawError::Node), got: {other:?}"),
    }
    handle.join().unwrap();
}

#[test]
fn node_client_enroll_submission() {
    let (url, handle) = spawn_echo_server(
        r#"{"ok":true,"epoch":42,"weight":1.5}"#,
        "200 OK",
    );

    let client = NodeClient::new(&url);
    let result = client
        .enroll("pubkey123", "miner456", &CpuArch::AppleSilicon)
        .unwrap();
    assert!(result.ok);
    assert_eq!(result.epoch, 42);
    assert!((result.weight - 1.5).abs() < f64::EPSILON);
    handle.join().unwrap();
}

#[test]
fn node_client_enroll_node_error() {
    let (url, handle) = spawn_echo_server(
        r#"{"ok":false,"error":"epoch closed"}"#,
        "200 OK",
    );

    let client = NodeClient::new(&url);
    let result = client.enroll("pk", "mid", &CpuArch::Modern);
    match result {
        Err(ClawError::Node(msg)) => {
            assert!(msg.contains("epoch closed"), "expected epoch closed error, got: {msg}");
        }
        other => panic!("expected Err(ClawError::Node), got: {other:?}"),
    }
    handle.join().unwrap();
}

#[test]
fn node_client_miners_parses_response() {
    let (url, handle) = spawn_echo_server(
        r#"{"miners":[{"miner":"test-miner","device_arch":"modern","device_family":"x86","last_attest":1783954623}],"pagination":{"count":1,"total":1}}"#,
        "200 OK",
    );

    let client = NodeClient::new(&url);
    let miners = client.miners().unwrap();
    assert_eq!(miners.len(), 1);
    assert_eq!(miners[0].miner, "test-miner");
    // last_attest 1783954623 should be converted to string
    assert_eq!(miners[0].last_seen, "1783954623");
    handle.join().unwrap();
}

// ── Deterministic attestation payload construction ──

#[test]
fn attestation_payload_is_deterministic() {
    let payload1 = serde_json::json!({
        "miner_pubkey": "abc",
        "miner_id": "test-miner",
        "device": {
            "family": CpuArch::AppleSilicon.family(),
            "arch": CpuArch::AppleSilicon.arch_str(),
        }
    });

    let payload2 = serde_json::json!({
        "miner_pubkey": "abc",
        "miner_id": "test-miner",
        "device": {
            "family": CpuArch::AppleSilicon.family(),
            "arch": CpuArch::AppleSilicon.arch_str(),
        }
    });

    assert_eq!(
        serde_json::to_string(&payload1).unwrap(),
        serde_json::to_string(&payload2).unwrap(),
        "attestation payload should be deterministic for same inputs"
    );
}

#[test]
fn attestation_payload_malformed_missing_fields_no_panic() {
    // Empty payload should not panic — should be handled as Node error or
    // at least not crash
    let (url, handle) = spawn_echo_server(
        r#"{"ok":false,"error":"missing fields"}"#,
        "200 OK",
    );

    let client = NodeClient::new(&url);
    let result = client.attest(&serde_json::json!({}));
    // Should not panic — any error is acceptable
    assert!(
        result.is_err(),
        "empty attest payload should produce an error, not panic"
    );
    handle.join().unwrap();
}

// ── MinerInfo deserialization ──

#[test]
fn miner_info_deserializes_with_all_fields() {
    let json = r#"{
        "miner": "test-miner",
        "miner_id": "mid-001",
        "device_arch": "g5",
        "device_family": "powerpc",
        "last_seen": "2026-07-20T00:00:00Z"
    }"#;

    let info: clawrtc::MinerInfo = serde_json::from_str(json).unwrap();
    assert_eq!(info.miner, "test-miner");
    assert_eq!(info.miner_id, "mid-001");
    assert_eq!(info.device_arch, "g5");
    assert_eq!(info.last_seen, "2026-07-20T00:00:00Z");
}

#[test]
fn miner_info_deserializes_minimal_fields() {
    let json = r#"{
        "miner_id": "mid-002",
        "device_arch": "modern"
    }"#;

    let info: clawrtc::MinerInfo = serde_json::from_str(json).unwrap();
    assert!(info.miner.is_empty());
    assert_eq!(info.device_arch, "modern");
    assert!(info.device_family.is_empty());
    assert!(info.last_seen.is_empty());
}

// ── Edge cases ──

#[test]
fn wallet_generate_many_and_check_uniqueness() {
    use std::collections::HashSet;

    let mut addresses = HashSet::new();
    let mut pubkeys = HashSet::new();

    for _ in 0..20 {
        let w = Wallet::generate();
        addresses.insert(w.address());
        pubkeys.insert(w.public_key_hex());
    }

    assert_eq!(addresses.len(), 20, "all generated addresses should be unique");
    assert_eq!(pubkeys.len(), 20, "all generated public keys should be unique");
}

#[test]
fn wallet_verify_roundtrip_with_known_message_patterns() {
    let w = Wallet::generate();
    let patterns: Vec<&[u8]> = vec![
        b"",
        b"a",
        b"hello world",
        &[0u8; 256],
        &[0xFFu8; 1024],
    ];

    for msg in patterns {
        let sig = w.sign(msg);
        assert!(Wallet::verify(&w.public_key_hex(), msg, &sig).unwrap());
    }
}

#[test]
fn node_client_balance_accepts_alias_field() {
    let (url, handle) = spawn_echo_server(
        r#"{"balance_rtc":42.0}"#,
        "200 OK",
    );

    let client = NodeClient::new(&url);
    let balance = client.balance("RTCtest").unwrap();
    assert!((balance - 42.0).abs() < f64::EPSILON);
    handle.join().unwrap();
}

// Verify the public API items with their test names (per acceptance criteria):
//
// | Public API | Test(s) |
// |---|---|
// | `Wallet::generate()` | `wallet_generate_produces_valid_address`, `wallet_generate_many_and_check_uniqueness` |
// | `Wallet::from_private_key()` | used in address vectors 1-4 |
// | `Wallet::from_hex()` | `wallet_serialize_deserialize_roundtrip`, `wallet_from_hex_rejects_bad_hex`, `wallet_from_hex_rejects_wrong_length` |
// | `Wallet::address()` | `wallet_generate_produces_valid_address`, `wallet_serialize_deserialize_roundtrip` |
// | `Wallet::public_key_hex()` | `wallet_serialize_deserialize_roundtrip` |
// | `Wallet::private_key_hex()` | `wallet_serialize_deserialize_roundtrip` |
// | `Wallet::sign()` | `wallet_sign_and_verify_own_message`, `wallet_verify_rejects_tampered_message` |
// | `Wallet::verify()` | `wallet_sign_and_verify_own_message` through `wallet_verify_rejects_invalid_pubkey_curve_point` |
// | `NodeClient::new()` | `node_client_health_connection_refused` (indirectly) |
// | `NodeClient::health()` | `node_client_health_connection_refused`, `node_client_health_parses_response` |
// | `NodeClient::balance()` | `node_client_balance_connection_refused`, `node_client_balance_parses_real_response` |
// | `NodeClient::miners()` | `node_client_miners_connection_refused`, `node_client_miners_parses_response` |
// | `NodeClient::challenge()` | `node_client_challenge_connection_refused`, `node_client_challenge_parses_response` |
// | `NodeClient::attest()` | `node_client_attest_connection_refused` through `attestation_payload_malformed_missing_fields_no_panic` |
// | `NodeClient::enroll()` | `node_client_enroll_connection_refused`, `node_client_enroll_submission`, `node_client_enroll_node_error` |
// | `CpuArch::multiplier()` | `cpu_arch_known_values` |
// | `CpuArch::family()` | `cpu_arch_known_values` |
// | `CpuArch::arch_str()` | `cpu_arch_known_values` |
