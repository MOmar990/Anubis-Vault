# Anubis Vault

![Python](https://img.shields.io/badge/Python-3.6%2B-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/Status-Active-brightgreen)

*ZAP!* Seal your secrets in the **Anubis Vault**, where the Egyptian god of protection guards your files with AES-256 encryption and mystical steganography. This powerful Python tool combines security, stealth, and a vibrant, comic-book-style interface, with a dependency wizard to summon required relics (`cryptography`, `stegano`, `Pillow`, `colorama`). Perfect for guardians of sensitive data who crave an Anubis-inspired adventure!

## Introduction

The **Anubis Vault** is your sacred chamber for encrypting files with military-grade AES-256, hiding them in PNG sarcophagi, and compressing them for efficiency. Guided by Anubis, the guardian of secrets, the tool offers a colorful, user-friendly interface with progress spinners and hieroglyphic flair. Its dependency wizard ensures a smooth setup by automatically installing missing packages, making it ideal for developers, security enthusiasts, and fans of Egyptian mysticism.

## Features

- **AES-256 Encryption**: Seal scrolls with unbreakable encryption, protected by a sacred oath.
- **Steganography**: *BAM!* Conceal encrypted files in PNG sarcophagi for ultimate stealth.
- **File Compression**: Mummify files before sealing to save space and time.
- **Vibrant UI**: Navigate with a colorful, Anubis-themed interface, complete with spinners and comic-book zingers.
- **Dependency Wizard**: Summons missing relics (`cryptography`, `stegano`, `Pillow`, `colorama`) on first run.
- **Configurable Runes**: Carve settings like salt length or output directories in `anubis_config.json`.
- **Cross-Platform**: Operates in Windows, Linux, and macOS temples.
- **Integrity Checks**: Verifies scrolls with SHA-256 hashes to detect tampering.
- **Easter Egg**: Choose ritual “42” for a cosmic revelation!

## Installation

### Prerequisites
- Python 3.6 or higher.
- `pip` for summoning relics.

### Steps
1. **Enter the Temple**:
   ```bash
   git clone https://github.com/yourusername/anubis-vault.git
   cd anubis-vault
   ```

2. **Invoke the Vault**:
   ```bash
   python anubis_vault.py
   ```
   The **dependency wizard** will check for `cryptography`, `stegano`, `Pillow`, and `colorama`. If any are missing, it offers to summon them. Type `y` to let Anubis handle it!

3. **Manual Summoning** (if preferred):
   ```bash
   pip install cryptography stegano Pillow colorama
   ```

4. **Sacred Chamber** (recommended):
   ```bash
   python -m venv anubis_env
   source anubis_env/bin/activate  # On Windows: anubis_env\Scripts\activate
   pip install cryptography stegano Pillow colorama
   python anubis_vault.py
   ```

## Usage

1. **Open the Vault**:
   ```bash
   python anubis_vault.py
   ```
   Behold the sacred menu:
   ```
   ==============================
           Anubis Vault
   Protected by the Guardian of Secrets!
   ==============================
     [1] Seal Scroll
     [2] Release Scroll
     [3] Carve Runes
     [4] Depart
   ------------------------------
   Choose your ritual:
   ```

2. **Seal a Scroll**:
   - Choose `[1] Seal Scroll`.
   - Enter the absolute path to your scroll (e.g., `/path/to/secret_scroll.txt`).
   - Add more scrolls or proceed.
   - Swear a strong oath (12+ characters, mix letters, numbers, symbols).
   - Optionally conceal the sealed scroll in a PNG sarcophagus (needs a large image, e.g., 1920x1080).
   - Example:
     ```bash
     Scroll to seal (absolute path like /path/to/secret_scroll.txt, q to cancel): /home/user/secret_scroll.txt
     Add another scroll? (y/n): n
     Oath: ********
     Confirm oath: ********
     Hide in a sarcophagus? (y/n, needs a large PNG like 1920x1080): y
     Enter sarcophagus path (e.g., /path/to/sarcophagus.png, q to cancel): /home/user/sarcophagus.png
     ```
   - Output: Sealed scroll in `secure_files/encrypted/<timestamp>/` and optional stego PNG in `secure_files/stego/<timestamp>/`.

3. **Release a Scroll**:
   - Choose `[2] Release Scroll`.
   - Enter the path to the `.enc` scroll or stego `.png`.
   - Provide the sacred oath.
   - For stego, name the original scroll (e.g., `papyrus`).
   - Example:
     ```bash
     Scroll to release (.enc or .png, absolute path like /path/to/scroll, q to cancel): secure_files/stego/20250504_180303/sarcophagus.png
     Add another scroll? (y/n): n
     Oath: ********
     Original scroll name (no extension, e.g., papyrus, q to cancel): papyrus
     ```
   - Output: Released scroll in `secure_files/decrypted/<timestamp>/` with detected extension (e.g., `.txt`).

4. **Carve Runes**:
   - Choose `[3] Carve Runes`.
   - Adjust runes like `salt_length` with guidance from `anubis_config.json`.
   - Example:
     ```
     --- salt_length ---
     Inscription: Bytes for the salt. More = spicier security! Stick with 32 unless you're feeling wild.
     Current: 32
     New rune: 64
     ```

5. **Tips**:
   - Use absolute paths (e.g., `/home/user/secret_scroll.txt`).
   - Ensure sarcophagus PNGs are large enough (Anubis suggests dimensions if too small).
   - Cancel rituals with `q`.
   - Consult `anubis_config.json` for advanced runes.

## Screenshots

*Coming soon! Add hieroglyphs of the vibrant UI, sacred menu, or sealing ritual to showcase Anubis’ flair. For now, invoke the vault to witness the mysticism!*

## Troubleshooting

- **Wizard Fails to Summon**:
  - Ensure `pip` is ready:
    ```bash
    python -m ensurepip --upgrade
    python -m pip install --upgrade pip
    ```
  - Summon manually:
    ```bash
    pip install cryptography stegano Pillow colorama
    ```
  - Check permissions or use `--user`:
    ```bash
    pip install cryptography stegano Pillow colorama --user
    ```

- **Lost Scrolls**:
  - Use absolute paths (e.g., `/home/user/secret_scroll.txt`).
  - Ensure scrolls exist and are readable.

- **Small Sarcophagus**:
  - Anubis will suggest required dimensions (e.g., “Need a 1920x1080 PNG”).
  - Use a larger PNG or skip concealment.

- **Oath Forgotten**:
  - Ensure the oath matches the one used to seal.
  - Use strong oaths (12+ characters, mixed characters).

- **Still Cursed?**:
  - Open an issue on GitHub with the curse details and ritual steps.

## Contributing

Join Anubis’ guardians! To contribute:
1. Fork the temple.
2. Create a ritual branch (`git checkout -b ritual/awesome-rune`).
3. Inscribe changes (`git commit -m "Add awesome rune"`).
4. Push to the branch (`git push origin ritual/awesome-rune`).
5. Open a pull request with a clear inscription.

Keep the Anubis vibe, follow the code style, and add tests for new rituals.

## License

This project is guarded under the MIT License. See the [LICENSE](LICENSE) file for details.

## Contact

Questions or visions? Open an issue on GitHub or join the guardians. Let’s seal secrets with Anubis! *KA-BOOM!*