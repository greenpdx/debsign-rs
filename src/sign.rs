//! GPG signing and verification using sequoia-openpgp

use anyhow::{Context, Result};
use sequoia_openpgp::cert::prelude::*;
use sequoia_openpgp::crypto::Password;
use sequoia_openpgp::parse::{PacketParser, Parse};
use sequoia_openpgp::policy::StandardPolicy;
use sequoia_openpgp::serialize::stream::{Armorer, Message, Signer as OpenpgpSigner};
use sequoia_openpgp::Cert;
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;

/// GPG signer for creating detached signatures
pub struct Signer {
    cert: Cert,
    passphrase: Option<Password>,
}

impl Signer {
    /// Load a signing key from an ASCII-armored file
    pub fn from_file<P: AsRef<Path>>(path: P, passphrase: Option<&str>) -> Result<Self> {
        let mut file = File::open(path.as_ref()).context("Failed to open key file")?;
        let mut data = Vec::new();
        file.read_to_end(&mut data)?;

        let cert = Cert::from_bytes(&data).context("Failed to parse key file")?;

        Ok(Self {
            cert,
            passphrase: passphrase.map(|p| p.into()),
        })
    }

    /// Load a signing key from the GnuPG keyring by key ID
    pub fn from_keyring(key_id: &str, passphrase: Option<&str>) -> Result<Self> {
        // Try to find the key in the standard GnuPG directory
        let gnupg_home = std::env::var("GNUPGHOME")
            .unwrap_or_else(|_| format!("{}/.gnupg", std::env::var("HOME").unwrap_or_default()));

        let _secring_path = Path::new(&gnupg_home).join("private-keys-v1.d");

        // For GnuPG 2.1+, keys are stored differently
        // Try pubring.kbx first, then fall back to pubring.gpg
        let keyring_path = Path::new(&gnupg_home).join("pubring.kbx");
        let alt_keyring_path = Path::new(&gnupg_home).join("pubring.gpg");

        let cert = if keyring_path.exists() {
            Self::find_key_in_keybox(&keyring_path, key_id)?
        } else if alt_keyring_path.exists() {
            Self::find_key_in_keyring(&alt_keyring_path, key_id)?
        } else {
            anyhow::bail!(
                "No GnuPG keyring found. Please specify a key file with --key-file"
            );
        };

        Ok(Self {
            cert,
            passphrase: passphrase.map(|p| p.into()),
        })
    }

    fn find_key_in_keyring(path: &Path, key_id: &str) -> Result<Cert> {
        let file = File::open(path)?;
        let ppr = PacketParser::from_reader(file)?;

        for cert in CertParser::from(ppr) {
            let cert = cert?;
            let fp = cert.fingerprint().to_hex();
            let keyid = cert.keyid().to_hex();

            if fp.ends_with(key_id) || keyid.ends_with(key_id) || key_id.contains(&keyid) {
                return Ok(cert);
            }

            // Also check user IDs
            for ua in cert.userids() {
                if let Ok(uid) = std::str::from_utf8(ua.value()) {
                    if uid.contains(key_id) {
                        return Ok(cert);
                    }
                }
            }
        }

        anyhow::bail!("Key '{}' not found in keyring", key_id);
    }

    fn find_key_in_keybox(_path: &Path, key_id: &str) -> Result<Cert> {
        // KBX format is more complex; for now, suggest using --key-file
        // A full implementation would parse the KBX format
        anyhow::bail!(
            "Reading from GnuPG 2.1+ keybox not fully supported. \
             Export your key with: gpg --export-secret-keys --armor {} > key.asc\n\
             Then use: debsign --key-file key.asc <deb-file>",
            key_id
        );
    }

    /// Create a detached ASCII-armored signature
    pub fn sign(&self, data: &str) -> Result<Vec<u8>> {
        let policy = StandardPolicy::new();

        // Find a signing-capable key
        let signing_key = self
            .cert
            .keys()
            .secret()
            .with_policy(&policy, None)
            .supported()
            .alive()
            .revoked(false)
            .for_signing()
            .next()
            .context("No signing-capable key found")?;

        // Decrypt the key if needed
        let signing_keypair = if signing_key.secret().is_encrypted() {
            let passphrase = self
                .passphrase
                .as_ref()
                .context("Key is encrypted but no passphrase provided")?;
            signing_key
                .key()
                .clone()
                .parts_into_secret()?
                .decrypt_secret(passphrase)?
                .into_keypair()?
        } else {
            signing_key.key().clone().parts_into_secret()?.into_keypair()?
        };

        // Create the signature
        let mut signature = Vec::new();
        {
            let message = Message::new(&mut signature);
            let message = Armorer::new(message).build()?;
            let mut signer = OpenpgpSigner::new(message, signing_keypair).detached().build()?;
            signer.write_all(data.as_bytes())?;
            signer.finalize()?;
        }

        Ok(signature)
    }
}

/// Result of signature verification
pub struct VerifyResult {
    pub valid: bool,
    pub signer: Option<String>,
}

/// GPG verifier for checking detached signatures
pub struct Verifier {
    certs: Vec<Cert>,
}

impl Verifier {
    /// Create a new verifier, loading public keys from the default keyring
    pub fn new() -> Result<Self> {
        let gnupg_home = std::env::var("GNUPGHOME")
            .unwrap_or_else(|_| format!("{}/.gnupg", std::env::var("HOME").unwrap_or_default()));

        let keyring_path = Path::new(&gnupg_home).join("pubring.gpg");
        let mut certs = Vec::new();

        if keyring_path.exists() {
            let file = File::open(&keyring_path)?;
            let ppr = PacketParser::from_reader(file)?;
            for cert in CertParser::from(ppr) {
                if let Ok(cert) = cert {
                    certs.push(cert);
                }
            }
        }

        Ok(Self { certs })
    }

    /// Verify a detached signature
    pub fn verify(&self, data: &str, signature: &[u8]) -> Result<VerifyResult> {
        use sequoia_openpgp::parse::stream::*;

        let policy = StandardPolicy::new();

        struct Helper<'a> {
            certs: &'a [Cert],
            result: VerifyResult,
        }

        impl<'a> VerificationHelper for Helper<'a> {
            fn get_certs(&mut self, ids: &[openpgp::KeyHandle]) -> Result<Vec<Cert>> {
                let mut result = Vec::new();
                for cert in self.certs {
                    for id in ids {
                        if cert.key_handle().aliases(id) {
                            result.push(cert.clone());
                            break;
                        }
                    }
                }
                Ok(result)
            }

            fn check(&mut self, structure: MessageStructure) -> Result<()> {
                for layer in structure {
                    match layer {
                        MessageLayer::SignatureGroup { results } => {
                            for result in results {
                                match result {
                                    Ok(GoodChecksum { ka, .. }) => {
                                        self.result.valid = true;
                                        let cert = ka.cert();
                                        if let Some(uid) = cert.userids().next() {
                                            self.result.signer = Some(
                                                String::from_utf8_lossy(uid.value()).to_string(),
                                            );
                                        }
                                    }
                                    Err(_) => {}
                                }
                            }
                        }
                        _ => {}
                    }
                }
                Ok(())
            }
        }

        let helper = Helper {
            certs: &self.certs,
            result: VerifyResult {
                valid: false,
                signer: None,
            },
        };

        let mut verifier = DetachedVerifierBuilder::from_bytes(signature)?
            .with_policy(&policy, None, helper)?;

        verifier.verify_bytes(data.as_bytes())?;

        let helper = verifier.into_helper();
        Ok(helper.result)
    }
}

use sequoia_openpgp as openpgp;
