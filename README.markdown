# Advanced Encryption Tool

A Python-based command-line tool for secure file encryption, decryption, and steganography. This tool uses AES-256 encryption with PBKDF2 key derivation, supports file compression, and offers optional steganography to hide encrypted files within PNG images. It is designed for ease of use, security, and flexibility, making it suitable for protecting sensitive files.

## Features

- **AES-256 Encryption**: Encrypt files using AES-256 in CBC mode with secure key derivation (PBKDF2, SHA256).
- **File Compression**: Compress files using gzip and ZIP before encryption to reduce size.
- **Steganography**: Hide encrypted files in PNG images using least significant bit (LSB) steganography, with capacity checks and retry prompts.
- **File Type Detection**: Automatically detect and restore file extensions (`.txt`, `.pdf`, `.docx`, etc.) during decryption.
- **Path Handling**: Supports paths with spaces and `~` expansion for user convenience.
- **Configurability**: Customize settings like salt length, iterations, and output directories via `encryption_config.json`.
- **Integrity Checks**: Verify file integrity using SHA256 hashes during decryption.
- **Temporary File Cleanup**: Automatically remove temporary files after processing (configurable).
- **Multiple File Support**: Encrypt or decrypt multiple files in a single session.

## Installation

### Prerequisites
- Python 3.6 or higher
- Required Python packages:
  - `cryptography`
  - `stegano`
  - `Pillow`

### Setup
1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/advanced-encryption-tool.git
   cd advanced-encryption-tool
   ```

2. Install dependencies:
   ```bash
   pip install cryptography stegano Pillow
   ```

3. Ensure `encryption_config.json` is in the project directory (included in the repository).

4. Run the tool:
   ```bash
   python enhanced-encryption-tool.py
   ```

## Usage

Launch the tool with:
```bash
python enhanced-encryption-tool.py
```

### Main Menu
```
Advanced Encryption Tool
1. Encrypt file
2. Decrypt file
3. Configure settings
4. Exit

Select an option:
```

#### 1. Encrypt File
- Input one or more file paths (absolute paths recommended, e.g., `/path/to/file.pdf`).
- Supports paths with spaces and `~` expansion.
- Enter and confirm a password.
- Optionally hide the encrypted file in a PNG image (steganography).
- Output: Encrypted files in `secure_files/encrypted/<timestamp>/` (`.enc`) or stego images in `secure_files/stego/<timestamp>/` (`.png`).

**Example**:
```
Select an option: 1
Enter the file path to encrypt (e.g., /path/to/file.pdf): /path/to/document.pdf
Add another file? (y/n): n
Enter password: ******
Confirm password: ******
Compressed: /path/to/document.pdf -> .temp/document.pdf.zip (123456 bytes)
Successfully encrypted: /path/to/document.pdf -> secure_files/encrypted/20250504_180303/document.pdf.enc
Hide in image? (y/n): y
Enter the carrier image path (e.g., /path/to/image.png): /path/to/carrier.png
Hiding data: secure_files/encrypted/20250504_180303/document.pdf.enc (123456 bytes, hash: abc123..., base64: 164608 bytes)
Stego image saved: secure_files/stego/20250504_180303/carrier.png (345678 bytes)
```

#### 2. Decrypt File
- Input paths to `.enc` files or stego `.png` files.
- Enter the password used for encryption.
- For stego, provide the original file name (without extension).
- Output: Decrypted files in `secure_files/decrypted/<timestamp>/` with detected extensions (e.g., `.pdf`, `.docx`).

**Example**:
```
Select an option: 2
Enter the file path to decrypt (e.g., /path/to/file.enc or /path/to/file.png): secure_files/encrypted/20250504_180303/document.pdf.enc
Add another file? (y/n): n
Enter password: ******
Decrypted: secure_files/encrypted/20250504_180303/document.pdf.enc -> secure_files/decrypted/20250504_180304/document (123456 bytes)
Successfully decrypted: secure_files/encrypted/20250504_180303/document.pdf.enc -> secure_files/decrypted/20250504_180304/document.pdf (123456 bytes)
```

#### 3. Configure Settings
- Modify settings like PBKDF2 iterations, salt length, output directories, or compression level.
- Changes are saved to `encryption_config.json`.

**Example**:
```
Select an option: 3
Current Configuration:
salt_length: 32
iv_length: 16
...
Enter new values (press Enter to keep current):
PBKDF2 iterations [500000]: 600000
...
Configuration saved successfully
```

#### 4. Exit
- Exit the tool.

### Steganography Notes
- **Carrier Image**: Use a PNG, JPG, BMP, GIF, TIFF, or WebP image with sufficient capacity (width × height / 8 bytes).
- **Capacity Check**: If the carrier is too small, the tool prompts to retry with a larger image or skip steganography.
- **Decryption**: For stego images, you must provide the original file name (without extension) to restore the file.

## File Structure
- `enhanced-encryption-tool.py`: Main script.
- `encryption_config.json`: Configuration file.
- `.temp/`: Temporary directory for compression and stego processing (cleaned up by default).
- `secure_files/`:
  - `encrypted/<timestamp>/`: Encrypted `.enc` files.
  - `decrypted/<timestamp>/`: Decrypted files.
  - `stego/<timestamp>/`: Stego PNG images.

## Configuration
Edit `encryption_config.json` to customize:
- `salt_length`: Salt length for key derivation (default: 32 bytes).
- `iv_length`: Initialization vector length (default: 16 bytes).
- `key_length`: AES key length (default: 32 bytes for AES-256).
- `iterations`: PBKDF2 iterations (default: 500000).
- `compression_level`: ZIP compression level (1–9, default: 9).
- `output_dir`: Base output directory (default: `secure_files`).
- `temp_dir`: Temporary directory (default: `.temp`).
- `stego_dir`: Stego output directory (default: `secure_files/stego`).
- `hash_algorithm`: Hash algorithm for integrity (default: `sha256`).
- `cleanup_temp`: Remove temporary files (default: `true`).

## Security Considerations
- **Password**: Choose a strong password; it’s critical for AES-256 security.
- **Steganography**: Ensure carrier images are large enough for the encrypted data (base64 increases size by ~33%).
- **Temporary Files**: Enable `cleanup_temp` to avoid leaving sensitive data on disk.
- **Integrity**: The tool verifies file integrity during decryption using SHA256 hashes.

## Contributing
Contributions are welcome! To contribute:
1. Fork the repository.
2. Create a feature branch (`git checkout -b feature/YourFeature`).
3. Commit your changes (`git commit -m 'Add YourFeature'`).
4. Push to the branch (`git push origin feature/YourFeature`).
5. Open a pull request.

Please include tests and update documentation for new features.

## Issues
Report bugs or suggest features by opening an issue on the [GitHub repository](https://github.com/yourusername/advanced-encryption-tool/issues).

## License
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Acknowledgments
Built with Python and powered by:
- [cryptography](https://cryptography.io/)
- [stegano](https://github.com/cedricbonhomme/Stegano)
- [Pillow](https://pillow.readthedocs.io/)