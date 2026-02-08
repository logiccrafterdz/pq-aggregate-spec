//! Wallet Generator CLI.
//!
//! Generates a deterministic keystore from a BIP-39 mnemonic.
//!
//! Usage:
//!   cargo run --bin wallet-gen -- --mnemonic "word1 word2 ..." --output "path/to/keystore"

use std::env;
use std::path::PathBuf;
use pq_aggregate::hsm::SoftwareHSM;

fn main() {
    let args: Vec<String> = env::args().collect();
    
    let mut mnemonic = String::new();
    let mut output_path = String::new();
    
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--mnemonic" => {
                if i + 1 < args.len() {
                    mnemonic = args[i + 1].clone();
                    i += 1;
                }
            }
            "--output" => {
                if i + 1 < args.len() {
                    output_path = args[i + 1].clone();
                    i += 1;
                }
            }
            _ => {}
        }
        i += 1;
    }
    
    if mnemonic.is_empty() {
        // Generate new if not provided?
        // For audit, we want deterministic.
        eprintln!("Usage: wallet-gen --mnemonic \"...\" --output \"...\"");
        std::process::exit(1);
    }
    
    if output_path.is_empty() {
        output_path = "keystore.enc".to_string();
    }
    
    println!("Initializing Software HSM...");
    println!("Keystore Path: {}", output_path);
    
    let hsm = match SoftwareHSM::new(PathBuf::from(&output_path), &mnemonic) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("Failed to initialize HSM: {}", e);
            std::process::exit(1);
        }
    };
    
    println!("Generating and encrypting keypair...");
    match hsm.generate_and_save() {
        Ok(pk) => {
            println!("Success! Keystore saved to {}", output_path);
            println!("Public Key (hex): {}", hex::encode(pk));
        },
        Err(e) => {
            eprintln!("Failed to generate key: {}", e);
            std::process::exit(1);
        }
    }
}
