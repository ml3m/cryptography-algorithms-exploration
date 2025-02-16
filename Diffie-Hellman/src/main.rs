extern crate rand;
use std::io::{self, Write};

fn mod_exp(base: u64, exp: u64, modulus: u64) -> u64 {
    let mut result = 1;
    let mut base = base % modulus;
    let mut exp = exp;

    while exp > 0 {
        if exp % 2 == 1 {
            result = (result * base) % modulus;
        }
        exp = exp >> 1;
        base = (base * base) % modulus;
    }
    result
}

fn read_input(prompt: &str) -> u64 {
    print!("{}", prompt);
    io::stdout().flush().unwrap(); // Ensure prompt is printed before reading
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    input.trim().parse().unwrap()
}

fn main() {
    // Get the prime number (p) and base (g) from user input
    let p = read_input("Enter a prime number (p): ");
    let g = read_input("Enter the base (g): ");

    // Get private keys for Alice and Bob
    let a = read_input("Enter Alice's private key: ");
    let b = read_input("Enter Bob's private key: ");

    // Compute the public keys
    let avar = mod_exp(g, a, p); // Alice's public key
    let bvar = mod_exp(g, b, p); // Bob's public key

    println!("\nPrime number (p): {}", p);
    println!("Base (g): {}", g);
    println!("Alice's private key: {}", a);
    println!("Bob's private key: {}", b);
    println!("Alice's public key: {}", avar);
    println!("Bob's public key: {}", bvar);

    // Exchange public keys (this is done securely in a real-world scenario)
    println!("\nExchanging public keys...");

    // Alice computes the shared secret using Bob's public key
    let shared_secret_alice = mod_exp(bvar, a, p);
    // Bob computes the shared secret using Alice's public key
    let shared_secret_bob = mod_exp(avar, b, p);

    println!("\nAlice's computed shared secret: {}", shared_secret_alice);
    println!("Bob's computed shared secret: {}", shared_secret_bob);

    // Verify that the shared secrets are the same
    if shared_secret_alice == shared_secret_bob {
        println!("\nThe shared secret is the same! Key exchange successful.");
    } else {
        println!("\nThe shared secrets do not match. Something went wrong.");
    }
}
