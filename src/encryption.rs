use anyhow::anyhow;
use chacha20poly1305::{
    aead::{stream, Aead, NewAead},
    XChaCha20Poly1305,
};
use rand::{rngs::OsRng, Rng};
use std::{
    fs::{self, File},
    io::{Read, Write},
};

//pub static CONF_PATH: &'static str = "~/.config/cencrypt/";

pub enum FileSize {
    Small,
    Large,
}

pub struct CryptPack {
    file_path: String,
    enc_file_path: String,
    dec_file_path: String,
    key: [u8; 32],
    nonce: [u8; 24],
    file_size: FileSize,
}

impl CryptPack {
    pub fn new(path: &str) -> anyhow::Result<Self> {
        let file = get_file(path)?;
        let (file_key, file_nonce) = gen_keys();
        let file_size = get_file_size(&file)?;
        let enc_file_path = format!("{}{}", path, ".cenc");
        let dec_file_path = format!("{}{}", path, ".dec");
        return Ok(CryptPack {
            file_path: path.into(),
            enc_file_path,
            dec_file_path,
            key: file_key,
            nonce: file_nonce,
            file_size,
        });
    }

    pub fn encrypt(&self) -> Result<(), anyhow::Error> {
    match self.file_size {
        FileSize::Small => {
            println!("Encrypting small file {}...", self.file_path);
            let cipher = XChaCha20Poly1305::new(&self.key.into());
            let file_data = fs::read(&self.file_path)?;
            let encrypted_file = cipher
                .encrypt(&self.nonce.into(), file_data.as_ref())
                .map_err(|e| anyhow!("Small file encryption err: {}", e))?;

            fs::write(&self.enc_file_path, encrypted_file)?;
        }
        FileSize::Large => {
            println!("Encrypting large file {}...", self.file_path);
            let cipher = XChaCha20Poly1305::new(&self.key.into());
            let mut stream_encryptor =
                stream::EncryptorBE32::from_aead(cipher, self.nonce.as_ref().into());

            const BUFFER_SIZE: usize = 1024 * 1024;
            let mut buf = [0u8; BUFFER_SIZE];
            let mut out_file = File::create(&self.enc_file_path)?;
            let mut in_file = File::open(&self.file_path)?;

            loop {
                let read_count = in_file.read(&mut buf)?;

                if read_count == BUFFER_SIZE {
                    let ciphertext = stream_encryptor
                        .encrypt_next(buf.as_slice())
                        .map_err(|e| anyhow!("Large file encryption err: {}", e))?;
                    out_file.write(&ciphertext)?;
                } else {
                    let ciphertext = stream_encryptor
                        .encrypt_last(buf.as_slice())
                        .map_err(|e| anyhow!("Large file encryption err: {}", e))?;
                    out_file.write(&ciphertext)?;
                    break;
                }
            }
        }
    }
    Ok(())
}

pub fn decrypt(self) -> Result<(), anyhow::Error> {
    match self.file_size {
        FileSize::Small => {
            let cipher = XChaCha20Poly1305::new(&self.key.into());

            let file_data = fs::read(&self.enc_file_path)?;

            let decrypted_file = cipher
                .decrypt(&self.nonce.into(), file_data.as_ref())
                .map_err(|e| anyhow!("Small file decryption err: {}", e))?;
            fs::write(&self.dec_file_path, decrypted_file)?;
        }
        FileSize::Large => {
            let cipher = XChaCha20Poly1305::new(&self.key.into());
            let mut stream_decryptor =
                stream::DecryptorBE32::from_aead(cipher, self.nonce.as_ref().into());

            const BUFFER_SIZE: usize = 1024 * 1024;
            let mut buf = [0u8; BUFFER_SIZE];
            let mut out_file = File::create(&self.dec_file_path)?;
            let mut in_file = File::open(self.enc_file_path)?;

            loop {
                let read_count = in_file.read(&mut buf)?;

                if read_count == BUFFER_SIZE {
                    let plaintext = stream_decryptor
                        .decrypt_next(buf.as_slice())
                        .map_err(|e| anyhow!("Large file decryption err: {}", e))?;
                    out_file.write(&plaintext)?;
                } else {
                    let plaintext = stream_decryptor
                        .decrypt_last(buf.as_slice())
                        .map_err(|e| anyhow!("Large file decryption err: {}", e))?;
                    out_file.write(&plaintext)?;
                    break;
                }
            }
        }
    }
    Ok(())
}


}

fn gen_keys() -> ([u8; 32], [u8; 24]) {
    let mut file_key = [0u8; 32];
    let mut file_nonce = [0u8; 24];
    OsRng.fill(&mut file_key);
    OsRng.fill(&mut file_nonce);
    return (file_key, file_nonce);
}

fn get_file(path: &str) -> anyhow::Result<File> {
    let file = File::open(path)?;
    return Ok(file);
}

pub fn get_file_size(file: &File) -> anyhow::Result<FileSize> {
    let metadata = file.metadata()?;
    let size = metadata.len();
    if size < 1024 * 1024 {
        return Ok(FileSize::Small);
    } else {
        return Ok(FileSize::Large);
    }
}

