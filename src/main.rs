/**
 * Plans for the future:
 * - key stretching
 * - PKCS7 padding
 */
use aes_gcm::{
    aead::{Aead, generic_array::GenericArray,
        AeadCore, KeyInit}, Aes256Gcm
};
use rand::rngs::OsRng;
use aes_gcm::aead::consts::U32;
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::PathBuf;
use clap::{arg, command, Command, value_parser};
use rpassword::prompt_password;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

fn main() {
    // Parse command-line arguments
    let m = cli().get_matches();

    // Determine encryption or decryption mode.
    let encrypt: &bool = m.get_one::<bool>("encrypt").unwrap();
    let decrypt: &bool = m.get_one::<bool>("decrypt").unwrap();

    // Get the input file path.
    let input_file: PathBuf = m.get_one::<PathBuf>("input_file").unwrap().to_path_buf();

    // Get the key file path (if provided).
    let key_file: Option<&PathBuf> = m.get_one::<PathBuf>("key_file");

    // Load or generate encryption key.
    let key = match key_file {
        Some(path) => {
            if path.exists() {
                let mut file = File::open(&path).expect("ERROR: Failed to open key file.");
                let mut key: Vec<u8> = vec![0u8; 32]; // 32 byte keys
                file.read_exact(&mut key).expect("ERROR: Failed to read key file.");
                key
            } else {
                eprintln!("ERROR: Key file does not exist.");
                std::process::exit(1);
            }
        },
        None => {
            let key: Vec<u8> = get_password();
            key
        },
    };

    // Initialize AES-256-GCM cipher with the key.
    let key: GenericArray<_, U32> = GenericArray::clone_from_slice(&key);
    let cipher = Aes256Gcm::new(&key);

    // Read the input file.
    let data = process_file(&input_file).expect("ERROR: Failed to process file");

    // Encrypt or decrypt the file based on the user selected mode.
    if *encrypt {
        let output_file = input_file.with_extension("enc");

        let nonce = Aes256Gcm::generate_nonce(&mut OsRng); // 96-bits = 12 bytes.
        let cipher_text = cipher.encrypt(&nonce, &*data).expect("ERROR: Encryption failed.");

        let mut output = File::create(&output_file).expect("ERROR: Failed to create output file.");
        output.write_all(&nonce).expect("ERROR: Failed to write nonce.");
        output.write_all(&cipher_text).expect("ERROR: Failed to write cipher_text.");
    } else if *decrypt {
        let output_file = input_file.with_extension("dec");

        let mut file_content = Vec::new();
        let mut file = File::open(&input_file).expect("ERROR: Failed to open input file.");
        file.read_to_end(&mut file_content).expect("ERROR: Failed to read file content.");

        let (nonce_buffer, cipher_text_buffer) = file_content.split_at(12); // Split at the first 12 bytes.
        let nonce = GenericArray::from_slice(nonce_buffer);

        let plaintext = cipher.decrypt(nonce, cipher_text_buffer).expect("ERROR: Decryption failed.");

        let mut output = File::create(&output_file).expect("ERROR: Failed to create output file.");
        output.write_all(&plaintext).expect("ERROR: Failed to write plaintext.");
    }

}

/// Hash the user password.
fn hash_password(password: &Vec<u8>, iterations: u32) -> Vec<u8> {
    let mut hasher = Sha256::new();
    let mut result = Vec::new();

    for _ in 0..iterations {
        let mut hasher_clone = hasher.clone();
        hasher_clone.update(password);
        result = hasher_clone.finalize().to_vec();
        hasher.reset();
    }

    result.to_vec()
}

/// Get the password from user.
fn get_password() -> Vec<u8> {
    let password = prompt_password("Enter password: ").unwrap();
    let password = password.trim();
    let mut password = password.as_bytes().to_vec();
    let key = hash_password(&password, 1000);
    password.zeroize(); // Remove secret from memory. (Remember free?)
    key
}

/// Reads in a file.
fn process_file(input_file: &PathBuf) -> io::Result<Vec<u8>> {
    let mut file = File::open(input_file)?;
    let mut data = Vec::new();
    file.read_to_end(&mut data)?;
    Ok(data)
}

/// Reads in user input for the specified arguments.
fn cli() -> Command {
    command!()
        .arg(arg!(encrypt: -e --encrypt)
            .conflicts_with("decrypt")
            .required(true))
        .arg(arg!(decrypt: -d --decrypt)
            .conflicts_with("encrypt")
            .required(true))
        .arg(arg!(key_file: -k --keyfile <keyfile>)
            .value_parser(value_parser!(PathBuf))
            .required(false))
        .arg(arg!(input_file: <file>)
            .value_parser(value_parser!(PathBuf))
            .required(true))
}
