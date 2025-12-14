//! Debian package (.deb) file handling
//!
//! A .deb file is an ar archive containing:
//! - debian-binary: version string (usually "2.0\n")
//! - control.tar.gz/xz/zst: package metadata
//! - data.tar.gz/xz/zst: package contents
//!
//! When signed, it also contains:
//! - _gpgorigin: detached GPG signature of the checksums

use anyhow::{Context, Result};
use md5::{Digest as _, Md5};
use sha1::Sha1;
use sha2::Sha256;
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;

/// Information about a member in the ar archive
#[derive(Debug, Clone)]
pub struct DebMember {
    pub name: String,
    pub size: u64,
    #[allow(dead_code)]
    pub offset: u64,
    pub md5: String,
    pub sha1: String,
    pub sha256: String,
}

/// Parsed .deb file
pub struct DebFile {
    pub path: std::path::PathBuf,
    pub members: Vec<DebMember>,
    pub signature: Option<Vec<u8>>,
}

impl DebFile {
    /// Open and parse a .deb file
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let file = File::open(&path).context("Failed to open file")?;
        let mut archive = ar::Archive::new(BufReader::new(file));

        let mut members = Vec::new();
        let mut signature = None;

        while let Some(entry) = archive.next_entry() {
            let mut entry = entry.context("Failed to read ar entry")?;
            let name = String::from_utf8_lossy(entry.header().identifier()).to_string();
            let size = entry.header().size();

            // Read the content for checksums
            let mut content = Vec::with_capacity(size as usize);
            entry.read_to_end(&mut content)?;

            if name == "_gpgorigin" {
                signature = Some(content);
                continue;
            }

            // Calculate checksums
            let md5 = format!("{:x}", Md5::digest(&content));
            let sha1 = format!("{:x}", Sha1::digest(&content));
            let sha256 = format!("{:x}", Sha256::digest(&content));

            members.push(DebMember {
                name,
                size,
                offset: 0, // We'll track this if needed
                md5,
                sha1,
                sha256,
            });
        }

        Ok(Self {
            path,
            members,
            signature,
        })
    }

    /// Generate the checksums document that will be signed
    pub fn generate_checksums(&self) -> Result<String> {
        let mut output = String::new();

        // MD5 checksums
        output.push_str("MD5:\n");
        for member in &self.members {
            output.push_str(&format!(
                " {} {} {}\n",
                member.md5, member.size, member.name
            ));
        }

        // SHA1 checksums
        output.push_str("SHA1:\n");
        for member in &self.members {
            output.push_str(&format!(
                " {} {} {}\n",
                member.sha1, member.size, member.name
            ));
        }

        // SHA256 checksums
        output.push_str("SHA256:\n");
        for member in &self.members {
            output.push_str(&format!(
                " {} {} {}\n",
                member.sha256, member.size, member.name
            ));
        }

        Ok(output)
    }

    /// Write a signed version of the deb file
    pub fn write_signed<P: AsRef<Path>>(&self, output_path: P, signature: &[u8]) -> Result<()> {
        let output_path = output_path.as_ref();

        // If output is the same as input, use a temp file
        let use_temp = output_path == self.path;
        let temp_file;
        let actual_output: &Path = if use_temp {
            temp_file = tempfile::NamedTempFile::new()?;
            temp_file.path()
        } else {
            output_path
        };

        // Open input
        let input_file = File::open(&self.path)?;
        let mut input_archive = ar::Archive::new(BufReader::new(input_file));

        // Create output
        let output_file = File::create(actual_output)?;
        let mut output_builder = ar::Builder::new(output_file);

        // First, add the signature as _gpgorigin (must be first for dpkg-sig compatibility)
        let mut sig_header = ar::Header::new(b"_gpgorigin".to_vec(), signature.len() as u64);
        sig_header.set_mode(0o100644);
        sig_header.set_mtime(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        );
        sig_header.set_uid(0);
        sig_header.set_gid(0);
        output_builder.append(&sig_header, signature)?;

        // Copy all other entries (except any existing _gpgorigin)
        while let Some(entry) = input_archive.next_entry() {
            let mut entry = entry?;
            let name = String::from_utf8_lossy(entry.header().identifier()).to_string();

            if name == "_gpgorigin" {
                // Skip existing signature
                continue;
            }

            let mut content = Vec::new();
            entry.read_to_end(&mut content)?;

            let mut header =
                ar::Header::new(entry.header().identifier().to_vec(), content.len() as u64);
            header.set_mode(entry.header().mode());
            header.set_mtime(entry.header().mtime());
            header.set_uid(entry.header().uid());
            header.set_gid(entry.header().gid());

            output_builder.append(&header, content.as_slice())?;
        }

        // Finalize
        drop(output_builder);

        // If we used a temp file, move it to the final destination
        if use_temp {
            std::fs::rename(actual_output, output_path)?;
        }

        Ok(())
    }
}
