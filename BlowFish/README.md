# BlowFish E/D

## Overview
This is an implementation of the Blowfish encryption algorithm in Rust. It allows encryption and decryption of files using a user-provided key.

## Features
- Encrypt and decrypt files using Blowfish.
- Supports keys up to 56 bytes in length.
- Pads input data to ensure compatibility with Blowfish's 8-byte block size.
- Provides meaningful error handling.

## Installation
Ensure you have Rust installed. If not, install it via [rustup](https://rustup.rs/):

```sh
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Clone the repository:

```sh
git clone https://github.com/yourusername/cryptography-algorithms-exploration.git
cd cryptography-algorithms-exploration/BlowFish
```

Build the project:

```sh
cargo build --release
```

## Usage
Run the Blowfish encryption program from the command line:

```sh
./target/release/BlowFish [-e|-d] key_file input_file output_file
```

### Arguments
- `-e` : Encrypt the input file.
- `-d` : Decrypt the input file.
- `key_file` : Path to the file containing the encryption key.
- `input_file` : Path to the file to be encrypted/decrypted.
- `output_file` : Path where the output should be saved.

### Example Usage
#### Encrypt a file
```sh
./target/release/BlowFish -e key.bin plaintext.txt encrypted.txt
```

#### Decrypt a file
```sh
./target/release/BlowFish -d key.bin encrypted.txt decrypted.txt
```

## Error Handling
The program provides the following errors:
- **InvalidKeyLength**: Key length must be between 1 and 56 bytes.
- **InvalidDataLength**: Input file must be a multiple of 8 bytes (handled via padding for encryption).
- **InvalidParameters**: Incorrect command-line arguments.
- **IO error**: File read/write issues.

## Implementation Details
The implementation follows these steps:
1. Initialize the Blowfish algorithm with predefined P-array and S-boxes.
2. Expand the key by XORing it with the P-array.
3. Encrypt or decrypt data in 8-byte blocks using the Feistel network.
4. For encryption, pad the data to be a multiple of 8 bytes.
5. For decryption, remove padding after processing.

## License
This project is licensed under the MIT License.

## Author
Developed by **[Your Name]**. Feel free to contribute or report issues!

