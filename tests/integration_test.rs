//! Integration tests for debsign
//!
//! Tests signing and verification of .deb packages using:
//! - debsign (our tool)
//! - dpkg-sig (system tool, for cross-verification if available)

use std::path::PathBuf;
use std::process::Command;

fn test_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests")
}

fn debsign_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join(if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        })
        .join("debsign")
}

fn unsigned_deb() -> PathBuf {
    test_dir().join("helloworld_0.1.0_arm64.deb")
}

fn signed_deb() -> PathBuf {
    test_dir().join("helloworld_signed_0.1.0_arm64.deb")
}

fn test_key() -> PathBuf {
    test_dir().join("test-key.asc")
}

fn test_public_key() -> PathBuf {
    test_dir().join("test-key-public.asc")
}

#[test]
fn test_unsigned_deb_exists() {
    assert!(
        unsigned_deb().exists(),
        "Unsigned test deb file should exist at {:?}",
        unsigned_deb()
    );
}

#[test]
fn test_key_exists() {
    assert!(test_key().exists(), "Test private key should exist");
    assert!(test_public_key().exists(), "Test public key should exist");
}

#[test]
fn test_unsigned_deb_has_no_signature() {
    let output = Command::new(debsign_binary())
        .args(["--verify", unsigned_deb().to_str().unwrap()])
        .output()
        .expect("Failed to run debsign");

    // Should fail because there's no signature
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stderr.contains("No signature") || stdout.contains("No signature"),
        "Should report no signature found"
    );
}

#[test]
fn test_sign_creates_signed_deb() {
    // Remove any existing signed deb
    let _ = std::fs::remove_file(signed_deb());

    // Sign the deb to a new file (preserving original unsigned)
    let sign_output = Command::new(debsign_binary())
        .args([
            "--key-file",
            test_key().to_str().unwrap(),
            "--output",
            signed_deb().to_str().unwrap(),
            unsigned_deb().to_str().unwrap(),
        ])
        .output()
        .expect("Failed to run debsign");

    assert!(
        sign_output.status.success(),
        "Signing should succeed: {}",
        String::from_utf8_lossy(&sign_output.stderr)
    );

    assert!(signed_deb().exists(), "Signed deb should be created");

    // Verify original is still unsigned
    let verify_original = Command::new(debsign_binary())
        .args(["--verify", unsigned_deb().to_str().unwrap()])
        .output()
        .expect("Failed to verify original");

    assert!(
        !verify_original.status.success(),
        "Original deb should still be unsigned"
    );
}

#[test]
fn test_verify_signed_deb() {
    // Ensure signed deb exists (sign if needed)
    if !signed_deb().exists() {
        let sign_output = Command::new(debsign_binary())
            .args([
                "--key-file",
                test_key().to_str().unwrap(),
                "--output",
                signed_deb().to_str().unwrap(),
                unsigned_deb().to_str().unwrap(),
            ])
            .output()
            .expect("Failed to run debsign");

        assert!(sign_output.status.success(), "Pre-signing should succeed");
    }

    // Import public key to keyring for verification
    let import_output = Command::new("gpg")
        .args(["--import", test_public_key().to_str().unwrap()])
        .output();

    if let Ok(output) = import_output {
        if output.status.success() {
            // Verify the signature with debsign
            let verify_output = Command::new(debsign_binary())
                .args(["--verify", signed_deb().to_str().unwrap()])
                .output()
                .expect("Failed to run debsign verify");

            let stdout = String::from_utf8_lossy(&verify_output.stdout);
            let stderr = String::from_utf8_lossy(&verify_output.stderr);

            // Should NOT say "No signature found"
            assert!(
                !stderr.contains("No signature found") && !stdout.contains("No signature found"),
                "Signed deb should have a signature"
            );
        }
    }
}

#[test]
fn test_verbose_shows_checksums() {
    let output = Command::new(debsign_binary())
        .args([
            "-V",
            "--key-file",
            test_key().to_str().unwrap(),
            unsigned_deb().to_str().unwrap(),
        ])
        .output()
        .expect("Failed to run debsign");

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Verbose output should show checksums
    assert!(stdout.contains("MD5:"), "Should show MD5 checksums");
    assert!(stdout.contains("SHA1:"), "Should show SHA1 checksums");
    assert!(stdout.contains("SHA256:"), "Should show SHA256 checksums");
}

#[test]
fn test_verbose_shows_deb_members() {
    let output = Command::new(debsign_binary())
        .args([
            "-V",
            "--key-file",
            test_key().to_str().unwrap(),
            unsigned_deb().to_str().unwrap(),
        ])
        .output()
        .expect("Failed to run debsign");

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Verbose output should show deb members
    assert!(
        stdout.contains("debian-binary"),
        "Should show debian-binary member"
    );
    assert!(
        stdout.contains("control.tar")
            || stdout.contains("control.tar.xz")
            || stdout.contains("control.tar.zst"),
        "Should show control.tar member"
    );
    assert!(
        stdout.contains("data.tar")
            || stdout.contains("data.tar.xz")
            || stdout.contains("data.tar.zst"),
        "Should show data.tar member"
    );
}

#[test]
fn test_dpkg_verify_signed_deb() {
    // This test requires dpkg-sig to be installed
    // Skip if not available

    let dpkg_sig_check = Command::new("which").arg("dpkg-sig").output();

    if dpkg_sig_check.is_err() || !dpkg_sig_check.unwrap().status.success() {
        eprintln!("Skipping dpkg-sig test: dpkg-sig not installed");
        return;
    }

    // Ensure signed deb exists
    if !signed_deb().exists() {
        let sign_output = Command::new(debsign_binary())
            .args([
                "--key-file",
                test_key().to_str().unwrap(),
                "--output",
                signed_deb().to_str().unwrap(),
                unsigned_deb().to_str().unwrap(),
            ])
            .output()
            .expect("Failed to run debsign");

        assert!(sign_output.status.success(), "Pre-signing should succeed");
    }

    // Import key to gpg keyring
    let _ = Command::new("gpg")
        .args(["--import", test_public_key().to_str().unwrap()])
        .output();

    // Verify with dpkg-sig
    let verify_output = Command::new("dpkg-sig")
        .args(["--verify", signed_deb().to_str().unwrap()])
        .output()
        .expect("Failed to run dpkg-sig");

    let stdout = String::from_utf8_lossy(&verify_output.stdout);
    let stderr = String::from_utf8_lossy(&verify_output.stderr);

    // dpkg-sig should recognize the signature
    // Note: It may report UNKNOWNSIG if key isn't trusted, but it should find *a* signature
    assert!(
        stdout.contains("GOODSIG")
            || stdout.contains("UNKNOWNSIG")
            || stderr.contains("GOODSIG")
            || stderr.contains("UNKNOWNSIG"),
        "dpkg-sig should find a signature in the signed deb.\nstdout: {}\nstderr: {}",
        stdout,
        stderr
    );
}
