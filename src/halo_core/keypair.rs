//! Ed25519 node identity management.

use anyhow::{Context, Result};
use base32::Alphabet;
use ed25519_dalek::SigningKey;
use ed25519_dalek::pkcs8::spki::der::pem::LineEnding;
use ed25519_dalek::pkcs8::{DecodePrivateKey, EncodePrivateKey};
use rand::rngs::OsRng;
use std::fmt;
use std::fs;
use std::path::Path;
use tracing::{Level, event};

const DEFAULT_KEY_PATH: &str = "node.key";

/// An Ed25519 keypair whose public key serves as the HALO NodeID.
pub struct Keypair {
    signing_key: SigningKey,
}

fn save_private_key(signing_key: &SigningKey, path: &Path) -> Result<()> {
    let pem = signing_key
        .to_pkcs8_pem(LineEnding::LF)
        .context("failed to encode private key as PEM")?;
    fs::write(path, pem.as_bytes())
        .with_context(|| format!("failed to write key file: {}", path.display()))?;
    Ok(())
}

fn load_private_key(path: &Path) -> Result<SigningKey> {
    let pem = fs::read_to_string(path)
        .with_context(|| format!("failed to read key file: {}", path.display()))?;
    SigningKey::from_pkcs8_pem(&pem)
        .with_context(|| format!("failed to parse private key: {}", path.display()))
}

impl Keypair {
    /// Loads the Ed25519 keypair from `node.key` in the current directory,
    /// generating and saving a new one if it does not exist yet.
    pub fn new() -> Result<Self> {
        Self::load_or_generate(DEFAULT_KEY_PATH)
    }

    /// Loads an Ed25519 keypair from `path`, or generates and persists a new one
    /// in PKCS#8 PEM format if `path` does not exist.
    pub fn load_or_generate(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        match fs::metadata(path) {
            Ok(_) => {
                event!(Level::DEBUG, path = %path.display(), "A private key already exists!");
                let signing_key = load_private_key(path)?;
                Ok(Self { signing_key })
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let signing_key = SigningKey::generate(&mut OsRng);
                save_private_key(&signing_key, path)?;
                Ok(Self { signing_key })
            }
            Err(e) => {
                Err(e).with_context(|| format!("failed to stat key file: {}", path.display()))
            }
        }
    }

    /// Returns the 32 raw Ed25519 public-key bytes used as the NodeID.
    pub fn node_id(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }
}

impl fmt::Display for Keypair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Only display the public key (z-base32 encoded) so secrets are never exposed.
        write!(f, "{}", base32::encode(Alphabet::Z, &self.node_id()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_and_reloads_same_keypair() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("node.key");

        let created = Keypair::load_or_generate(&path).unwrap();
        assert!(path.is_file());

        let reloaded = Keypair::load_or_generate(&path).unwrap();
        assert_eq!(created.node_id(), reloaded.node_id());
        assert_eq!(created.to_string(), reloaded.to_string());
    }

    #[test]
    fn rejects_corrupt_key_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.key");
        fs::write(&path, "not a pem key").unwrap();

        assert!(Keypair::load_or_generate(&path).is_err());
    }
}
