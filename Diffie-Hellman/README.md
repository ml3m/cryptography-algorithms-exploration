# Diffie-Hellman Key Exchange - Rust

This is a simple implementation of the **Diffie-Hellman key exchange protocol**
in Rust. The program demonstrates how two parties (Alice and Bob) can securely
share a secret key over an insecure channel using public-key cryptography.

## Features
- **Prime Number (`p`) and Base (`g`) input**: Users can input the prime number and base for the Diffie-Hellman protocol.
- **Private Key input**: Users can input the private keys for Alice and Bob.
- **Key Exchange**: The program computes the public keys for Alice and Bob, and then calculates the shared secret key for both.
- **Security**: The Diffie-Hellman protocol allows both parties to compute the same shared secret without directly transmitting it.

## Prerequisites
```toml
[dependencies]
rand = "0.8"
```

## Usage

when you run the program, you will be prompted to enter the following inputs:

1. **Prime number (`p`)**: A prime number that is publicly agreed upon by both parties.
2. **Base (`g`)**: A base number used for modular exponentiation.
3. **Alice's private key**: A secret number chosen by Alice.
4. **Bob's private key**: A secret number chosen by Bob.

### Example Interaction

```
Enter a prime number (p): 23
Enter the base (g): 5
Enter Alice's private key: 6
Enter Bob's private key: 15

Prime number (p): 23
Base (g): 5
Alice's private key: 6
Bob's private key: 15
Alice's public key: 8
Bob's public key: 19

Exchanging public keys...

Alice's computed shared secret: 2
Bob's computed shared secret: 2

The shared secret is the same! Key exchange successful.
```

## Code Explanation

- **Modular Exponentiation**: The core of the Diffie-Hellman key exchange uses modular exponentiation to compute public and shared keys. This is implemented in the `mod_exp` function.
- **Private Key Generation**: Private keys are randomly generated for Alice and Bob within the range `[1, p)`.
- **Public Key Calculation**: The public keys `A` and `B` are calculated using the formula:
  
  ```
  A = g^a mod p
  B = g^b mod p
  ```

- **Shared Secret Calculation**: Alice and Bob each calculate the shared secret using the other’s public key and their own private key:
  
  ```
  Shared Secret = B^a mod p (for Alice)
  Shared Secret = A^b mod p (for Bob)
  ```
