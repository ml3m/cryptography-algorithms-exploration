use std::env;
use std::fs;
use std::io::{self};
use thiserror::Error;
mod constants;
use constants::{P_ARRAY, S_BOXES};

#[derive(Error, Debug)]
pub enum BlowfishError {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
    #[error("Invalid key length")]
    InvalidKeyLength,
    #[error("Invalid data length")]
    InvalidDataLength,
    #[error("Invalid parameters")]
    InvalidParameters,
}

type Result<T> = std::result::Result<T, BlowfishError>;

pub struct Blowfish {
    p: [u32; 18],
    s: [[u32; 256]; 4],
}

impl Blowfish {
    pub fn new(key: &[u8]) -> Result<Self> {
        if key.is_empty() || key.len() > 56 {
            return Err(BlowfishError::InvalidKeyLength);
        }

        let mut bf = Blowfish {
            p: P_ARRAY,
            s: S_BOXES,
        };

        bf.expand_key(key);
        Ok(bf)
    }

    fn f(&self, x: u32) -> u32 {
        let a = (x >> 24) as usize;
        let b = ((x >> 16) & 0xff) as usize;
        let c = ((x >> 8) & 0xff) as usize;
        let d = (x & 0xff) as usize;

        ((self.s[0][a].wrapping_add(self.s[1][b])) ^ self.s[2][c])
            .wrapping_add(self.s[3][d])
    }

    fn expand_key(&mut self, key: &[u8]) {
        let mut key_pos = 0;
        let key_len = key.len();

        // XOR P-array with key bytes
        for p in self.p.iter_mut() {
            let mut data = 0u32;
            for _ in 0..4 {
                data = (data << 8) | key[key_pos] as u32;
                key_pos = (key_pos + 1) % key_len;
            }
            *p ^= data;
        }

        let mut l = 0u32;
        let mut r = 0u32;

        // Update P-array
        for i in (0..18).step_by(2) {
            let (new_l, new_r) = self.encrypt_block(l, r);
            self.p[i] = new_l;
            self.p[i + 1] = new_r;
            l = new_l;
            r = new_r;
        }

        // Update S-boxes
        for i in 0..4 {
            for j in (0..256).step_by(2) {
                let (new_l, new_r) = self.encrypt_block(l, r);
                self.s[i][j] = new_l;
                self.s[i][j + 1] = new_r;
                l = new_l;
                r = new_r;
            }
        }
    }

    fn encrypt_block(&self, mut l: u32, mut r: u32) -> (u32, u32) {
        for i in 0..16 {
            l ^= self.p[i];
            r ^= self.f(l);
            std::mem::swap(&mut l, &mut r);
        }
        std::mem::swap(&mut l, &mut r);
        r ^= self.p[16];
        l ^= self.p[17];
        (l, r)
    }

    fn decrypt_block(&self, mut l: u32, mut r: u32) -> (u32, u32) {
        for i in (2..18).rev() {
            l ^= self.p[i];
            r ^= self.f(l);
            std::mem::swap(&mut l, &mut r);
        }
        std::mem::swap(&mut l, &mut r);
        r ^= self.p[1];
        l ^= self.p[0];
        (l, r)
    }

    pub fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        let padding_len = (8 - (data.len() % 8)) % 8;
        let mut padded_data = data.to_vec();
        padded_data.extend(std::iter::repeat(padding_len as u8).take(padding_len));

        let mut result = Vec::with_capacity(padded_data.len());

        for chunk in padded_data.chunks(8) {
            let l = u32::from_be_bytes(chunk[0..4].try_into().unwrap());
            let r = u32::from_be_bytes(chunk[4..8].try_into().unwrap());
            let (new_l, new_r) = self.encrypt_block(l, r);
            result.extend_from_slice(&new_l.to_be_bytes());
            result.extend_from_slice(&new_r.to_be_bytes());
        }

        Ok(result)
    }

    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        if data.len() % 8 != 0 {
            return Err(BlowfishError::InvalidDataLength);
        }

        let mut result = Vec::with_capacity(data.len());

        for chunk in data.chunks(8) {
            let l = u32::from_be_bytes(chunk[0..4].try_into().unwrap());
            let r = u32::from_be_bytes(chunk[4..8].try_into().unwrap());
            let (new_l, new_r) = self.decrypt_block(l, r);
            result.extend_from_slice(&new_l.to_be_bytes());
            result.extend_from_slice(&new_r.to_be_bytes());
        }

        if let Some(&padding_len) = result.last() {
            if padding_len as usize <= 8 {
                result.truncate(result.len() - padding_len as usize);
            }
        }

        Ok(result)
    }
}


fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    
    if args.len() != 5 {
        eprintln!("Usage: {} [-e|-d] key_file input_file output_file", args[0]);
        return Err(BlowfishError::InvalidParameters);
    }

    let mode = &args[1];
    let key_path = &args[2];
    let input_path = &args[3];
    let output_path = &args[4];

    let key = fs::read(key_path)?;
    let input_data = fs::read(input_path)?;

    let cipher = Blowfish::new(&key)?;
    let result = match mode.as_str() {
        "-e" => cipher.encrypt(&input_data)?,
        "-d" => cipher.decrypt(&input_data)?,
        _ => return Err(BlowfishError::InvalidParameters),
    };

    fs::write(output_path, &result)?;
    
    println!("Successfully {} {} to {}", 
        if mode == "-e" { "encrypted" } else { "decrypted" },
        input_path,
        output_path
    );

    Ok(())
}
