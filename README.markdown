# Advanced Encryption Tool

![Python](https://img.shields.io/badge/Python-3.6%2B-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/Status-Active-brightgreen)

*ZAP!* Secure your files with military-grade AES-256 encryption, hide them in images like a comic-book ninja, and enjoy a colorful, user-friendly interface! The **Advanced Encryption Tool** is your go-to solution for protecting sensitive data, complete with a dependency wizard that magically handles setup. Perfect for developers, security enthusiasts, and anyone who loves a touch of superhero flair.

## Introduction

This tool combines robust AES-256 encryption, stealthy steganography, and file compression into a single, easy-to-use Python application. Whether you’re locking down documents or hiding secrets in PNGs, the tool’s vibrant UI and automated dependency wizard make it a breeze. Run it, follow the prompts, and let the wizard install any missing packages (`cryptography`, `stegano`, `Pillow`, `colorama`)—no cape required!

## Features

- **AES-256 Encryption**: Lock files with industry-standard encryption, secured by a password-derived key.
- **Steganography**: *BAM!* Hide encrypted files inside PNG images for extra stealth.
- **File Compression**: Squash files before encryption to save space and speed things up.
- **Colorful UI**: Enjoy a vibrant, comic-book-style interface with clear prompts, progress spinners, and organized output.
- **Dependency Wizard**: Automatically detects and installs missing dependencies on first run.
- **Configurable Settings**: Tweak salt length, PBKDF2 iterations, and output directories via a guided menu.
- **Cross-Platform**: Runs smoothly on Windows, Linux, and macOS.
- **Integrity Checks**: Verifies file integrity with SHA-256 hashes to detect tampering.
- **Easter Egg**: Try menu option “42” for a cosmic surprise!

## Installation

### Prerequisites
- Python 3.6 or higher.
- `pip` for installing dependencies.

### Steps
1. **Clone the Repository**:
   ```bash
   git clone https://github.com/yourusername/advanced-encryption-tool.git
   cd advanced-encryption-tool
   ```

2. **Run the Tool**:
   ```bash
   python enhanced-encryption-tool.py
   ```
   On first run, the **dependency wizard** checks for `cryptography`, `stegano`, `Pillow`, and `colorama`. If any are missing, it prompts to install them automatically. Just type `y` to let it work its magic!

3. **Manual Dependency Installation** (if you prefer):
   ```bash
   pip install cryptography stegano Pillow colorama
   ```

4. **Virtual Environment** (recommended):
   ```bash
   python -m venv myenv
   source myenv/bin/activate  # On Windows: myenv\Scripts\activate
   pip install cryptography stegano Pillow colorama
   python enhanced-encryption-tool.py
   ```

## Usage

1. **Launch the Tool**:
   ```bash
   python enhanced-encryption-tool.py
   ```
   You’ll see a colorful menu:
   ```
   ==============================
       Advanced Encryption Tool
     *ZAP!* Secure Files in a Snap!
   ==============================
     [1] Encrypt File
     [2] Decrypt File
     [3] Configure Settings
     [4] Exit
   ------------------------------
   Pick your poison:
   ```

2. **Encrypt a File**:
   - Choose `[1] Encrypt File`.
   - Enter the absolute path to your file (e.g., `/path/to/document.pdf`).
   - Add more files or proceed.
   - Set a strong password (12+ characters, mix letters, numbers, symbols).
   - Optionally hide the encrypted file in a PNG (needs a large image, e.g., 1920x1080).
   - Example:
     ```bash
     File to encrypt (absolute path like /path/to/file.pdf, q to cancel): /home/user/test.txt
     Add another file? (y/n): n
     Password: ********
     Confirm password: ********
     Hide in an image? (y/n, needs a big PNG like 1920x1080): y
     Enter image path (e.g., /path/to/image.png, q to cancel): /home/user/carrier.png
     ```
   - Output: Encrypted file in `secure_files/encrypted/<timestamp>/` and optional stego PNG in `secure_files/stego/<timestamp>/`.

3. **Decrypt a File**:
   - Choose `[2] Decrypt File`.
   - Enter the path to the `.enc` file or stego `.png`.
   - Provide the password.
   - For stego, specify the original file name (without extension).
   - Example:
     ```bash
     File to decrypt (.enc or .png, absolute path like /path/to/file, q to cancel): secure_files/stego/20250504_180303/carrier.png
     Add another file? (y/n): n
     Password: ********
     Original file name (no extension, e.g., example_file, q to cancel): test
     ```
   - Output: Decrypted file in `secure_files/decrypted/<timestamp>/` with detected extension (e.g., `.txt`).

4. **Configure Settings**:
   - Choose `[3] Configure Settings`.
   - Adjust settings like `salt_length` or `output_dir` with descriptions from `encryption_config.json`.
   - Example:
     ```
     --- salt_length ---
     Description: Bytes for the salt. More = spicier security! Stick with 32 unless you're feeling wild.
     Current: 32
     New value: 64
     ```

5. **Tips**:
   - Use absolute paths (e.g., `/home/user/file.txt`, not `file.txt`).
   - For stego, ensure the carrier image is large enough (tool suggests dimensions if too small).
   - Cancel any prompt with `q`.
   - Check `encryption_config.json` for advanced settings.

## Screenshots

*Coming soon! Add screenshots of the colorful UI, menu, or encryption process to showcase the comic-book style. For now, try running the tool to see the vibrant interface!*

## Troubleshooting

- **Dependency Wizard Fails**:
  - Ensure `pip` is installed and accessible:
    ```bash
    python -m ensurepip --upgrade
    python -m pip install --upgrade pip
    ```
  - Install manually:
    ```bash
    pip install cryptography stegano Pillow colorama
    ```
  - Check permissions or use `--user`:
    ```bash
    pip install cryptography stegano Pillow colorama --user
    ```

- **Path Errors**:
  - Use absolute paths (e.g., `/home/user/file.txt`).
  - Ensure files exist and are readable.

- **Stego Image Too Small**:
  - The tool will suggest required dimensions (e.g., “Need a 1920x1080 PNG”).
  - Use a larger PNG or skip stego.

- **Password Issues**:
  - Ensure the password matches the one used for encryption.
  - Use strong passwords (12+ characters, mixed characters).

- **Still Stuck?**:
  - Open an issue on GitHub with the error message and steps to reproduce.

## Contributing

We’d love your help to make this tool even more super! To contribute:
1. Fork the repository.
2. Create a feature branch (`git checkout -b feature/awesome-update`).
3. Commit changes (`git commit -m "Add awesome update"`).
4. Push to the branch (`git push origin feature/awesome-update`).
5. Open a pull request with a clear description.

Please follow the code style, keep the comic-book tone, and add tests for new features.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Contact

Have questions or ideas? Open an issue on GitHub or contribute directly. Let’s make encryption fun and secure! *WHAM!*