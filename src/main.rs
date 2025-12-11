use anyhow::{Context, Result};
use clap::Parser;
use std::path::PathBuf;

mod deb;
mod sign;

#[derive(Parser, Debug)]
#[command(name = "debsign")]
#[command(about = "Sign Debian packages with GPG", long_about = None)]
struct Args {
    /// Path to the .deb file to sign
    #[arg(required = true)]
    deb_file: PathBuf,

    /// GPG key ID or fingerprint to use for signing
    #[arg(short, long)]
    key: Option<String>,

    /// Path to secret key file (ASCII armored)
    #[arg(short = 'f', long = "key-file")]
    key_file: Option<PathBuf>,

    /// Passphrase for the secret key
    #[arg(short, long)]
    passphrase: Option<String>,

    /// Output file (default: overwrites input)
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// Verify signature instead of signing
    #[arg(short, long)]
    verify: bool,

    /// Show verbose output
    #[arg(short = 'V', long)]
    verbose: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();

    if args.verify {
        verify_deb(&args)?;
    } else {
        sign_deb(&args)?;
    }

    Ok(())
}

fn sign_deb(args: &Args) -> Result<()> {
    // Read and parse the deb file
    let deb_info = deb::DebFile::open(&args.deb_file)
        .with_context(|| format!("Failed to open deb file: {:?}", args.deb_file))?;

    if args.verbose {
        println!("Deb file: {:?}", args.deb_file);
        println!("Members:");
        for member in &deb_info.members {
            println!("  {} ({} bytes)", member.name, member.size);
        }
    }

    // Generate checksums
    let checksums = deb_info.generate_checksums()?;

    if args.verbose {
        println!("\nChecksums:");
        println!("{}", checksums);
    }

    // Load the signing key
    let signer = if let Some(key_file) = &args.key_file {
        sign::Signer::from_file(key_file, args.passphrase.as_deref())?
    } else if let Some(key_id) = &args.key {
        sign::Signer::from_keyring(key_id, args.passphrase.as_deref())?
    } else {
        anyhow::bail!("Either --key or --key-file must be specified");
    };

    // Sign the checksums
    let signature = signer.sign(&checksums)?;

    if args.verbose {
        println!("\nSignature generated ({} bytes)", signature.len());
    }

    // Write the signed deb
    let output_path = args.output.as_ref().unwrap_or(&args.deb_file);
    deb_info.write_signed(output_path, &signature)?;

    println!("Signed: {:?}", output_path);

    Ok(())
}

fn verify_deb(args: &Args) -> Result<()> {
    let deb_info = deb::DebFile::open(&args.deb_file)
        .with_context(|| format!("Failed to open deb file: {:?}", args.deb_file))?;

    if let Some(signature) = &deb_info.signature {
        if args.verbose {
            println!("Found signature in deb file");
        }

        // Regenerate checksums
        let checksums = deb_info.generate_checksums()?;

        // Verify
        let verifier = sign::Verifier::new()?;
        let result = verifier.verify(&checksums, signature)?;

        if result.valid {
            println!("Good signature from: {}", result.signer.unwrap_or_default());
            Ok(())
        } else {
            anyhow::bail!("BAD signature!");
        }
    } else {
        anyhow::bail!("No signature found in deb file");
    }
}
