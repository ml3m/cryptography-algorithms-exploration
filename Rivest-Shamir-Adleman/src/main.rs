use num_bigint::{BigInt, RandBigInt, ToBigInt};
use num_traits::{One, Zero};
use rand::thread_rng;

#[derive(Debug, Clone)]
pub struct RSAKeyPair {
    pub public_key: (BigInt, BigInt),  // (n, e)
    pub private_key: (BigInt, BigInt), // (n, d)
}

impl RSAKeyPair {
    pub fn new(bit_length: usize) -> Self {
        let mut rng = thread_rng();
        
        // Generate two large prime numbers
        let p = generate_prime(&mut rng, bit_length);
        let q = generate_prime(&mut rng, bit_length);
        
        // Calculate n = p * q
        let n = &p * &q;
        
        // Calculate φ(n) = (p-1)(q-1)
        let phi = (&p - 1_i32) * (&q - 1_i32);
        
        // Choose public exponent e
        let e = BigInt::from(65537_i32); // Common choice for e
        
        // Calculate private exponent d
        let d = mod_inverse(&e, &phi).unwrap();
        
        RSAKeyPair {
            public_key: (n.clone(), e),
            private_key: (n, d),
        }
    }

    pub fn encrypt(&self, message: &BigInt) -> BigInt {
        let (n, e) = &self.public_key;
        mod_pow(message, e, n)
    }

    pub fn decrypt(&self, ciphertext: &BigInt) -> BigInt {
        let (n, d) = &self.private_key;
        mod_pow(ciphertext, d, n)
    }
}

// Helper function to generate a prime number
fn generate_prime(rng: &mut impl RandBigInt, bit_length: usize) -> BigInt {
    loop {
        let num = rng.gen_bigint(bit_length as u64);
        if is_prime(&num) {
            return num;
        }
    }
}

// Simple primality test (for educational purposes)
fn is_prime(n: &BigInt) -> bool {
    if n <= &BigInt::one() {
        return false;
    }
    
    let two = 2.to_bigint().unwrap();
    if n == &two {
        return true;
    }
    
    if n.mod_floor(&two).is_zero() {
        return false;
    }
    
    let mut i = BigInt::from(3);
    while &i * &i <= *n {
        if n.mod_floor(&i).is_zero() {
            return false;
        }
        i += 2;
    }
    true
}

// Extended Euclidean Algorithm
fn extended_gcd(a: &BigInt, b: &BigInt) -> (BigInt, BigInt, BigInt) {
    if b.is_zero() {
        (a.clone(), BigInt::one(), BigInt::zero())
    } else {
        let (d, x, y) = extended_gcd(b, &a.mod_floor(b));
        (d, y.clone(), x - (a / b) * y)
    }
}

// Modular multiplicative inverse
fn mod_inverse(a: &BigInt, m: &BigInt) -> Option<BigInt> {
    let (g, x, _) = extended_gcd(a, m);
    if g != BigInt::one() {
        None
    } else {
        Some((x.mod_floor(m) + m).mod_floor(m))
    }
}

// Modular exponentiation
fn mod_pow(base: &BigInt, exponent: &BigInt, modulus: &BigInt) -> BigInt {
    let mut result = BigInt::one();
    let mut base = base.mod_floor(modulus);
    let mut exp = exponent.clone();
    
    while exp > BigInt::zero() {
        if exp.mod_floor(&BigInt::from(2)).is_one() {
            result = (result * &base).mod_floor(modulus);
        }
        base = (&base * &base).mod_floor(modulus);
        exp /= 2;
    }
    result
}

fn main() {
    // Example usage
    let key_pair = RSAKeyPair::new(512); // Generate 512-bit keys
    
    // Convert a message to BigInt
    let message = BigInt::from(12345);
    println!("Original message: {}", message);
    
    // Encrypt the message
    let encrypted = key_pair.encrypt(&message);
    println!("Encrypted message: {}", encrypted);
    
    // Decrypt the message
    let decrypted = key_pair.decrypt(&encrypted);
    println!("Decrypted message: {}", decrypted);
    
    assert_eq!(message, decrypted);
}
