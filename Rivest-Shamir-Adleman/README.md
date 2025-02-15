# RSA Implementation Notes

RSA (Rivest-Shamir-Adleman) is a widely used public-key cryptosystem for secure data transmission. This document provides a complete guide to implementing RSA, covering key generation, encryption, decryption, and important security considerations.

## 1. Mathematical Background

RSA relies on the mathematical properties of modular arithmetic and prime numbers.  The core idea is the difficulty of factoring large numbers.

*   **Prime Numbers:** Numbers divisible only by 1 and themselves.
*   **Modular Arithmetic:** Performing arithmetic operations within a specific modulus (remainder after division).  `a mod n` represents the remainder when `a` is divided by `n`.
*   **Euler's Totient Function (φ(n)):**  Counts the number of integers between 1 and `n` that are coprime to `n` (i.e., their greatest common divisor is 1).
    *   If `p` is prime, then `φ(p) = p - 1`.
    *   If `p` and `q` are distinct primes, then `φ(pq) = (p - 1)(q - 1)`.
*   **Euler's Theorem:** If `a` and `n` are coprime, then `a^φ(n) ≡ 1 (mod n)`.
*   **Modular Multiplicative Inverse:**  The inverse of `a` modulo `n` is an integer `b` such that `(a * b) mod n = 1`.  It exists if and only if `a` and `n` are coprime.

## 2. Key Generation

RSA key generation involves selecting two large prime numbers and deriving the public and private keys.

### 2.1. Steps

1.  **Choose two distinct prime numbers, `p` and `q`.** These should be large, randomly chosen primes.  The security of RSA depends heavily on the size of these primes.  Typically, `p` and `q` are hundreds or thousands of bits long.

2.  **Compute `n = p * q`.**  This is the modulus.  `n` is part of both the public and private keys.

3.  **Compute `φ(n) = (p - 1) * (q - 1)`.**  This is Euler's totient function of `n`.

4.  **Choose an integer `e` such that `1 < e < φ(n)` and `gcd(e, φ(n)) = 1`.**  `e` is the public exponent.  A common choice for `e` is 65537 (2<sup>16</sup> + 1), as it's a Fermat prime, making exponentiation faster.  However, smaller values of `e` can be vulnerable to certain attacks if not implemented carefully.

5.  **Compute `d`, the modular multiplicative inverse of `e` modulo `φ(n)`.**  This means finding `d` such that `(d * e) mod φ(n) = 1`.  `d` is the private exponent.  The Extended Euclidean Algorithm is commonly used to find the modular inverse.

### 2.2. Key Components

*   **Public Key:** `(n, e)`
*   **Private Key:** `(n, d)`  (or sometimes `(p, q, d)` for optimization)

### 2.3. Example

Let's use small primes for demonstration (in practice, these would be *much* larger):

1.  `p = 17`, `q = 11`
2.  `n = p * q = 17 * 11 = 187`
3.  `φ(n) = (p - 1) * (q - 1) = 16 * 10 = 160`
4.  Choose `e = 7`.  `gcd(7, 160) = 1`.
5.  Find `d` such that `(d * 7) mod 160 = 1`.  Using the Extended Euclidean Algorithm, we find `d = 23`.  (Because 7 * 23 = 161, and 161 mod 160 = 1)

*   **Public Key:** `(187, 7)`
*   **Private Key:** `(187, 23)`

### 2.4. Code Example (Python)

```python
import random
import math

def is_prime(n, k=5):
    """
    Miller-Rabin primality test.
    """
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0:
        return False

    r, s = 0, n - 1
    while s % 2 == 0:
        r += 1
        s //= 2

    for _ in range(k):
        a = random.randint(2, n - 2)
        x = pow(a, s, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def generate_prime(bits):
    """
    Generates a random prime number of the specified bit length.
    """
    while True:
        p = random.getrandbits(bits)
        p |= (1 << (bits - 1)) | 1  # Ensure it's odd and has the correct bit length
        if is_prime(p):
            return p

def gcd(a, b):
    """
    Calculates the greatest common divisor of a and b.
    """
    while b:
        a, b = b, a % b
    return a

def extended_gcd(a, b):
    """
    Extended Euclidean algorithm to find the modular inverse.
    Returns (gcd, x, y) such that ax + by = gcd.
    """
    if a == 0:
        return b, 0, 1
    d, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return d, x, y

def mod_inverse(a, m):
    """
    Calculates the modular multiplicative inverse of a modulo m.
    """
    g, x, y = extended_gcd(a, m)
    if g != 1:
        raise Exception('Modular inverse does not exist')
    else:
        return x % m

def generate_keys(bits):
    """
    Generates RSA public and private keys.
    """
    p = generate_prime(bits // 2)
    q = generate_prime(bits // 2)

    while p == q:
        q = generate_prime(bits // 2)

    n = p * q
    phi = (p - 1) * (q - 1)

    # Choose e such that 1 < e < phi and gcd(e, phi) = 1
    e = random.randrange(1, phi)
    g = gcd(e, phi)
    while g != 1:
        e = random.randrange(1, phi)
        g = gcd(e, phi)

    # Use a fixed e
    e = 65537

    d = mod_inverse(e, phi)

    return (n, e), (n, d)

# Example usage:
bits = 256  # Key size in bits
public_key, private_key = generate_keys(bits)
print("Public Key (n, e):", public_key)
print("Private Key (n, d):", private_key)
```

## 3. Encryption

Encryption involves transforming the plaintext message into ciphertext using the public key.

### 3.1. Steps

1.  **Obtain the recipient's public key `(n, e)`.**
2.  **Represent the plaintext message `M` as an integer between 0 and `n - 1`.**  This might involve padding and encoding the message.  Padding is crucial for security (see Section 5).
3.  **Compute the ciphertext `C = M^e mod n`.**

### 3.2. Example

Using the keys from the previous example:

*   Public Key: `(187, 7)`
*   Let's encrypt the message `M = 88`.

`C = 88^7 mod 187 = 11`

Therefore, the ciphertext is `C = 11`.

### 3.3. Code Example (Python)

```python
def encrypt(message, public_key):
    """
    Encrypts a message using the RSA public key.
    """
    n, e = public_key
    # Ensure the message is an integer
    if not isinstance(message, int):
        raise TypeError("Message must be an integer")
    # Ensure the message is within the valid range
    if message < 0 or message >= n:
        raise ValueError("Message must be between 0 and n-1")

    ciphertext = pow(message, e, n)
    return ciphertext

# Example usage:
message = 88
public_key = (187, 7)
ciphertext = encrypt(message, public_key)
print("Plaintext:", message)
print("Ciphertext:", ciphertext)
```

## 4. Decryption

Decryption involves transforming the ciphertext back into the original plaintext message using the private key.

### 4.1. Steps

1.  **Obtain the ciphertext `C`.**
2.  **Obtain the private key `(n, d)`.**
3.  **Compute the plaintext `M = C^d mod n`.**

### 4.2. Example

Using the ciphertext from the previous example:

*   Ciphertext: `C = 11`
*   Private Key: `(187, 23)`

`M = 11^23 mod 187 = 88`

Therefore, the original message is `M = 88`.

### 4.3. Code Example (Python)

```python
def decrypt(ciphertext, private_key):
    """
    Decrypts a ciphertext using the RSA private key.
    """
    n, d = private_key
    plaintext = pow(ciphertext, d, n)
    return plaintext

# Example usage:
ciphertext = 11
private_key = (187, 23)
plaintext = decrypt(ciphertext, private_key)
print("Ciphertext:", ciphertext)
print("Plaintext:", plaintext)
```

## 5. Padding Schemes

Padding is essential for the security of RSA.  Without padding, RSA is vulnerable to several attacks.  Padding schemes add structure and randomness to the message before encryption.

### 5.1. Importance of Padding

*   **Preventing Homomorphic Properties:**  Without padding, RSA has a homomorphic property: `(M1^e * M2^e) mod n = (M1 * M2)^e mod n`. This can be exploited.
*   **Preventing Small Message Attacks:** If the message `M` is small, `M^e` might be smaller than `n`, and `M^e mod n` is simply `M^e`.  An attacker can take the `e`-th root of the ciphertext to recover `M`.
*   **Preventing Common Modulus Attacks:** If multiple parties use the same modulus `n` with different public exponents `e`, and encrypt the same message `M`, an attacker can recover `M`.

### 5.2. Common Padding Schemes

*   **PKCS#1 v1.5:**  A simple padding scheme, but it has known vulnerabilities.  It's generally *not* recommended for new applications.
*   **OAEP (Optimal Asymmetric Encryption Padding):**  A more secure padding scheme that is recommended for new applications.  OAEP uses a random oracle to add randomness and structure to the message.

### 5.3. OAEP Overview

OAEP involves the following steps:

1.  **Message Padding:** The message `M` is padded with zeros to a certain length.
2.  **Random Mask Generation:** A random seed `r` is generated.  This seed is used to generate a mask for the padded message.
3.  **Masking:** The padded message is XORed with the mask.
4.  **Seed Masking:** The seed `r` is also masked using a hash of the masked message.
5.  **Concatenation:** The masked message and masked seed are concatenated to form the padded message that is then encrypted.

### 5.4. Code Example (Python - OAEP)

This example uses the `cryptography` library, which provides a secure and well-tested implementation of OAEP.

```python
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend

def generate_rsa_key():
    """
    Generates an RSA key pair.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def encrypt_oaep(message, public_key):
    """
    Encrypts a message using RSA with OAEP padding.
    """
    ciphertext = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

def decrypt_oaep(ciphertext, private_key):
    """
    Decrypts a ciphertext using RSA with OAEP padding.
    """
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext

# Example usage:
private_key, public_key = generate_rsa_key()
message = b"This is a secret message."  # Message must be bytes

ciphertext = encrypt_oaep(message, public_key)
print("Ciphertext:", ciphertext)

plaintext = decrypt_oaep(ciphertext, private_key)
print("Plaintext:", plaintext.decode())
```

**Important:**  Always use a well-vetted cryptography library for padding and encryption/decryption.  Do not attempt to implement OAEP or other complex padding schemes yourself unless you are an experienced cryptographer.

## 6. Implementation Considerations

*   **Key Size:**  The key size (number of bits in `n`) is a critical security parameter.  Shorter keys are faster but less secure.  As of 2024, a key size of at least 2048 bits is recommended.  4096 bits is even better for long-term security.
*   **Prime Number Generation:**  Generating strong, random primes is crucial.  Use a cryptographically secure random number generator (CSPRNG) and primality tests like Miller-Rabin.  Ensure that `p` and `q` are sufficiently different in size to prevent certain factorization attacks.
*   **Side-Channel Attacks:**  RSA implementations can be vulnerable to side-channel attacks, such as timing attacks, power analysis attacks, and electromagnetic radiation attacks.  These attacks exploit information leaked during the computation process.  Countermeasures include:
    *   **Constant-time implementations:** Ensure that the execution time of operations does not depend on the secret key.
    *   **Blinding:**  Randomize the input to the exponentiation operation.
    *   **Masking:**  Mask the secret key with random values.
*   **Error Handling:**  Implement robust error handling to prevent information leakage.  For example, don't reveal whether a decryption operation failed due to an invalid signature or an invalid ciphertext.
*   **Library Usage:**  Use well-established and audited cryptography libraries (e.g., OpenSSL, Bouncy Castle, cryptography.io) whenever possible.  These libraries provide secure and efficient implementations of RSA and other cryptographic algorithms.  Avoid rolling your own crypto unless you have extensive expertise in cryptography.
*   **Key Storage:**  Securely store private keys.  Use hardware security modules (HSMs) or secure enclaves for the most sensitive keys.  Encrypt private keys at rest.
*   **Random Number Generation:** Use a cryptographically secure pseudo-random number generator (CSPRNG) for all random number generation, including key generation and padding.  In Python, use `secrets` module or `os.urandom`.
*   **Parameter Validation:** Validate all input parameters, such as key sizes, exponents, and messages, to prevent unexpected behavior and potential vulnerabilities.
*   **Regular Updates:** Stay up-to-date with the latest security recommendations and best practices for RSA.  New attacks and vulnerabilities are discovered regularly.

## 7. Common Attacks and Countermeasures

*   **Factoring Attacks:** The most fundamental attack against RSA is to factor the modulus `n` into its prime factors `p` and `q`.  The security of RSA relies on the difficulty of factoring large numbers.  Countermeasure: Use sufficiently large key sizes (2048 bits or more).
*   **Small `e` Attacks:** If the public exponent `e` is too small, RSA can be vulnerable to attacks.  Countermeasure: Use a larger value for `e`, such as 65537.  If a small `e` is necessary, use proper padding.
*   **Wiener's Attack:**  If the private exponent `d` is too small relative to `n`, Wiener's attack can recover `d`.  Countermeasure: Ensure that `d` is sufficiently large.
*   **Common Modulus Attack:** If multiple parties use the same modulus `n` with different public exponents `e`, and encrypt the same message `M`, an attacker can recover `M`.  Countermeasure: Never reuse the same modulus `n` for different key pairs.
*   **Chosen Ciphertext Attacks (CCA):**  RSA is vulnerable to chosen ciphertext attacks if not used with proper padding.  Countermeasure: Use OAEP or other CCA-secure padding schemes.
*   **Timing Attacks:**  Timing attacks exploit variations in the execution time of RSA operations to recover the private key.  Countermeasure: Use constant-time implementations.
*   **Power Analysis Attacks:**  Power analysis attacks measure the power consumption of a device during RSA operations to recover the private key.  Countermeasure: Use power analysis-resistant implementations.
