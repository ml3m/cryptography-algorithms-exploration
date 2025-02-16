use std::convert::TryInto;
use std::fs::File;
use std::io::{Read, Write};
use std::env;

const CONSTANTS: [u32; 4] = [
    0x61707865, // "expa"
    0x3320646e, // "nd 3"
    0x79622d32, // "2-by"
    0x6b206574, // "te k"
];

fn quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    state[a] = state[a].wrapping_add(state[b]); state[d] ^= state[a]; state[d] = state[d].rotate_left(16);
    state[c] = state[c].wrapping_add(state[d]); state[b] ^= state[c]; state[b] = state[b].rotate_left(12);
    state[a] = state[a].wrapping_add(state[b]); state[d] ^= state[a]; state[d] = state[d].rotate_left(8);
    state[c] = state[c].wrapping_add(state[d]); state[b] ^= state[c]; state[b] = state[b].rotate_left(7);
}

fn chacha20_block(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> [u8; 64] {
    let mut state = [
        CONSTANTS[0], CONSTANTS[1], CONSTANTS[2], CONSTANTS[3],
        u32::from_le_bytes(key[0..4].try_into().unwrap()),
        u32::from_le_bytes(key[4..8].try_into().unwrap()),
        u32::from_le_bytes(key[8..12].try_into().unwrap()),
        u32::from_le_bytes(key[12..16].try_into().unwrap()),
        u32::from_le_bytes(key[16..20].try_into().unwrap()),
        u32::from_le_bytes(key[20..24].try_into().unwrap()),
        u32::from_le_bytes(key[24..28].try_into().unwrap()),
        u32::from_le_bytes(key[28..32].try_into().unwrap()),
        counter,
        u32::from_le_bytes(nonce[0..4].try_into().unwrap()),
        u32::from_le_bytes(nonce[4..8].try_into().unwrap()),
        u32::from_le_bytes(nonce[8..12].try_into().unwrap()),
    ];
    
    let initial_state = state;
    
    for _ in 0..10 {
        quarter_round(&mut state, 0, 4, 8, 12);
        quarter_round(&mut state, 1, 5, 9, 13);
        quarter_round(&mut state, 2, 6, 10, 14);
        quarter_round(&mut state, 3, 7, 11, 15);
        quarter_round(&mut state, 0, 5, 10, 15);
        quarter_round(&mut state, 1, 6, 11, 12);
        quarter_round(&mut state, 2, 7, 8, 13);
        quarter_round(&mut state, 3, 4, 9, 14);
    }
    
    for i in 0..16 {
        state[i] = state[i].wrapping_add(initial_state[i]);
    }
    
    let mut output = [0u8; 64];
    for i in 0..16 {
        output[i * 4..(i + 1) * 4].copy_from_slice(&state[i].to_le_bytes());
    }
    output
}

fn chacha20_encrypt_decrypt(key: &[u8; 32], nonce: &[u8; 12], counter: u32, data: &[u8]) -> Vec<u8> {
    let mut output = vec![0u8; data.len()];
    for (i, chunk) in data.chunks(64).enumerate() {
        let keystream = chacha20_block(key, counter + i as u32, nonce);
        for (j, &byte) in chunk.iter().enumerate() {
            output[i * 64 + j] = byte ^ keystream[j];
        }
    }
    output
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 4 {
        eprintln!("Usage: {} [-e|-d] <input_file> <output_file>", args[0]);
        return;
    }

    let mode = &args[1];
    let input_file = &args[2];
    let output_file = &args[3];

    if mode != "-e" && mode != "-d" {
        eprintln!("Invalid mode: {}. Use -e for encryption or -d for decryption.", mode);
        return;
    }

    let mut file = File::open(input_file).expect("Failed to open input file");
    let mut data = Vec::new();
    file.read_to_end(&mut data).expect("Failed to read file");

    let key = [0u8; 32];
    let nonce = [0u8; 12];
    let result = chacha20_encrypt_decrypt(&key, &nonce, 1, &data);

    let mut output = File::create(output_file).expect("Failed to create output file");
    output.write_all(&result).expect("Failed to write to output file");

    println!("{} completed: {} -> {}", if mode == "-e" { "Encryption" } else { "Decryption" }, input_file, output_file);
}
