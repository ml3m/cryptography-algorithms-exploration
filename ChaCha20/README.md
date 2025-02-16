# ChaCha20 E/D

using the ChaCha20 algorithm.

## Features
- Supports encryption and decryption.
- Reads and writes to files.
- Takes command-line arguments to specify the operation mode, input file, and output file.

## Usage

1. **Encrypt a file:**
   ```
   cargo run -e <input_file> <output_file>
   ```

2. **Decrypt a file:**
   ```
   cargo run -d <input_file> <output_file>
   ```

### Arguments:
- `-e` for encryption.
- `-d` for decryption.
- `<input_file>` is the file to be encrypted/decrypted.
- `<output_file>` is the result file to store the encrypted/decrypted data.

## Notes:
- The key and nonce are hardcoded as zero arrays for simplicity.
- The input and output files are binary, so make sure to handle them accordingly.

## Example:
```bash
cargo run -e plaintext.txt encrypted.bin
cargo run -d encrypted.bin decrypted.txt
```

