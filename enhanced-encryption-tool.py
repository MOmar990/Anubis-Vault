import os
import json
import zipfile
import hashlib
import secrets
import shutil
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.padding import PKCS7
from getpass import getpass

class EncryptionConfig:
    """Configuration management for encryption settings."""
    DEFAULT_CONFIG = {
        'salt_length': 32,          # Increased from 16
        'iv_length': 16,
        'key_length': 32,
        'iterations': 500000,       # Increased from 100000
        'compression_level': 9,
        'output_dir': 'secure_files',
        'temp_dir': '.temp',
        'hash_algorithm': 'sha256',
        'cleanup_temp': True,
        'archive_previous': True
    }

    def __init__(self, config_file: str = 'encryption_config.json'):
        self.config_file = config_file
        self.config = self.DEFAULT_CONFIG.copy()
        self.load_config()

    def load_config(self) -> None:
        """Load configuration from file."""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    loaded_config = json.load(f)
                    self.config.update(loaded_config)
        except Exception as e:
            print(f"Error loading config: {e}")

    def save_config(self) -> bool:
        """Save current configuration to file."""
        try:
            with open(self.config_file, 'w') as f:
                json.dump(self.config, f, indent=4)
            return True
        except Exception as e:
            print(f"Error saving config: {e}")
            return False

    def get(self, key: str):
        """Get configuration value."""
        return self.config.get(key, self.DEFAULT_CONFIG.get(key))

    def set(self, key: str, value) -> None:
        """Set configuration value."""
        if key in self.DEFAULT_CONFIG:
            self.config[key] = value
        else:
            raise ValueError(f"Invalid configuration key: {key}")

class SecureFileHandler:
    """Handles secure file operations with integrity checks."""
    def __init__(self, config: EncryptionConfig):
        self.config = config
        self._setup_directories()

    def _setup_directories(self) -> None:
        """Set up necessary directories."""
        os.makedirs(self.config.get('output_dir'), exist_ok=True)
        os.makedirs(self.config.get('temp_dir'), exist_ok=True)

    def _calculate_file_hash(self, file_path: str) -> str:
        """Calculate file hash using configured algorithm."""
        hash_func = getattr(hashlib, self.config.get('hash_algorithm'))()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                hash_func.update(chunk)
        return hash_func.hexdigest()

    def _generate_output_path(self, base_path: str, operation: str) -> str:
        """Generate unique output path."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_dir = Path(self.config.get('output_dir')) / operation / timestamp
        os.makedirs(output_dir, exist_ok=True)
        return str(output_dir / Path(base_path).name)

    def compress_files(self, input_path: str, zip_path: str) -> bool:
        """Compress files with integrity check."""
        try:
            with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED, 
                               compresslevel=self.config.get('compression_level')) as zipf:
                if os.path.isfile(input_path):
                    zipf.write(input_path, os.path.basename(input_path))
                else:
                    for root, _, files in os.walk(input_path):
                        for file in files:
                            file_path = os.path.join(root, file)
                            arcname = os.path.relpath(file_path, input_path)
                            zipf.write(file_path, arcname)
            
            # Verify zip file integrity
            with zipfile.ZipFile(zip_path, 'r') as zipf:
                if zipf.testzip() is not None:
                    raise zipfile.BadZipFile("Zip file integrity check failed")
            return True
        except Exception as e:
            print(f"Compression error: {e}")
            return False

class SecureEncryption:
    """Enhanced encryption with additional security features."""
    def __init__(self, config: EncryptionConfig):
        self.config = config
        self.file_handler = SecureFileHandler(config)

    def derive_key(self, password: str, salt: bytes) -> bytes:
        """Derive encryption key with enhanced security."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.config.get('key_length'),
            salt=salt,
            iterations=self.config.get('iterations'),
            backend=default_backend()
        )
        return kdf.derive(password.encode())

    def encrypt_file(self, input_path: str, password: str) -> Optional[str]:
        """Encrypt file with enhanced security features."""
        try:
            # Generate secure random values
            salt = secrets.token_bytes(self.config.get('salt_length'))
            iv = secrets.token_bytes(self.config.get('iv_length'))
            
            # Calculate input file hash
            input_hash = self.file_handler._calculate_file_hash(input_path)
            
            # Derive key
            key = self.derive_key(password, salt)
            
            # Setup encryption
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            
            # Generate output path
            output_path = self.file_handler._generate_output_path(input_path, 'encrypted')
            output_path += '.enc'
            
            with open(input_path, 'rb') as in_file, open(output_path, 'wb') as out_file:
                # Write metadata
                out_file.write(salt)
                out_file.write(iv)
                out_file.write(input_hash.encode())
                
                # Encrypt data
                padder = PKCS7(128).padder()
                while True:
                    chunk = in_file.read(8192)
                    if not chunk:
                        break
                    padded_chunk = padder.update(chunk)
                    encrypted_chunk = encryptor.update(padded_chunk)
                    out_file.write(encrypted_chunk)
                
                # Finalize encryption
                padded_chunk = padder.finalize()
                encrypted_chunk = encryptor.update(padded_chunk) + encryptor.finalize()
                out_file.write(encrypted_chunk)
            
            return output_path
        except Exception as e:
            print(f"Encryption error: {e}")
            return None

    def decrypt_file(self, input_path: str, password: str) -> Optional[str]:
        """Decrypt file with integrity verification."""
        try:
            with open(input_path, 'rb') as f:
                # Read metadata
                salt = f.read(self.config.get('salt_length'))
                iv = f.read(self.config.get('iv_length'))
                stored_hash = f.read(64).decode()  # SHA256 hash is 64 chars
                
                # Derive key
                key = self.derive_key(password, salt)
                
                # Setup decryption
                cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
                decryptor = cipher.decryptor()
                unpadder = PKCS7(128).unpadder()
                
                # Generate output path
                output_path = self.file_handler._generate_output_path(input_path, 'decrypted')
                if output_path.endswith('.enc'):
                    output_path = output_path[:-4]
                
                with open(output_path, 'wb') as out_file:
                    while True:
                        chunk = f.read(8192)
                        if not chunk:
                            break
                        decrypted_chunk = decryptor.update(chunk)
                        try:
                            if not f.peek(1):  # Last chunk
                                decrypted_chunk = unpadder.update(decrypted_chunk) + unpadder.finalize()
                            else:
                                decrypted_chunk = unpadder.update(decrypted_chunk)
                            out_file.write(decrypted_chunk)
                        except ValueError:
                            os.remove(output_path)
                            return None
                
                # Verify file integrity
                decrypted_hash = self.file_handler._calculate_file_hash(output_path)
                if decrypted_hash != stored_hash:
                    os.remove(output_path)
                    raise ValueError("File integrity check failed")
                
                return output_path
        except Exception as e:
            print(f"Decryption error: {e}")
            return None

class AdvancedEncryptionTool:
    """Main class for the advanced encryption tool."""
    def __init__(self):
        self.config = EncryptionConfig()
        self.encryption = SecureEncryption(self.config)
        
    def configure(self) -> None:
        """Configure encryption settings."""
        print("\nCurrent Configuration:")
        for key, value in self.config.config.items():
            print(f"{key}: {value}")
        
        print("\nModify settings (press Enter to keep current value):")
        
        try:
            # Security settings
            iterations = input(f"PBKDF2 iterations [{self.config.get('iterations')}]: ")
            if iterations.isdigit():
                self.config.set('iterations', int(iterations))
            
            salt_length = input(f"Salt length in bytes [{self.config.get('salt_length')}]: ")
            if salt_length.isdigit():
                self.config.set('salt_length', int(salt_length))
            
            # Output settings
            output_dir = input(f"Output directory [{self.config.get('output_dir')}]: ")
            if output_dir:
                self.config.set('output_dir', output_dir)
            
            # Compression settings
            comp_level = input(f"Compression level (1-9) [{self.config.get('compression_level')}]: ")
            if comp_level.isdigit() and 1 <= int(comp_level) <= 9:
                self.config.set('compression_level', int(comp_level))
            
            # Save configuration
            if self.config.save_config():
                print("Configuration saved successfully!")
            else:
                print("Failed to save configuration!")
                
        except Exception as e:
            print(f"Error during configuration: {e}")

    def process_files(self, operation: str, input_paths: List[str], password: str) -> None:
        """Process multiple files for encryption or decryption."""
        temp_dir = Path(self.config.get('temp_dir'))
        
        for input_path in input_paths:
            try:
                if not os.path.exists(input_path):
                    print(f"Path not found: {input_path}")
                    continue
                
                if operation == 'encrypt':
                    # Compress first if it's encryption
                    zip_path = temp_dir / f"{Path(input_path).name}.zip"
                    if self.encryption.file_handler.compress_files(input_path, str(zip_path)):
                        # Encrypt the zip file
                        encrypted_path = self.encryption.encrypt_file(str(zip_path), password)
                        if encrypted_path:
                            print(f"Successfully encrypted: {input_path} -> {encrypted_path}")
                    
                elif operation == 'decrypt':
                    # Decrypt the file
                    decrypted_path = self.encryption.decrypt_file(input_path, password)
                    if decrypted_path:
                        # Extract if it's a zip file
                        try:
                            extract_dir = Path(decrypted_path).parent / Path(decrypted_path).stem
                            with zipfile.ZipFile(decrypted_path, 'r') as zipf:
                                zipf.extractall(extract_dir)
                            os.remove(decrypted_path)  # Remove zip file after extraction
                            print(f"Successfully decrypted: {input_path} -> {extract_dir}")
                        except zipfile.BadZipFile:
                            print(f"Successfully decrypted: {input_path} -> {decrypted_path}")
                    else:
                        print(f"Failed to decrypt: {input_path}")
                
            except Exception as e:
                print(f"Error processing {input_path}: {e}")
            
            finally:
                # Cleanup temporary files
                if self.config.get('cleanup_temp'):
                    shutil.rmtree(temp_dir)
                    os.makedirs(temp_dir)

    def run(self) -> None:
        """Main program loop."""
        while True:
            print("\nAdvanced Encryption Tool")
            print("1. Encrypt files/directories")
            print("2. Decrypt files")
            print("3. Configure settings")
            print("4. Exit")
            
            choice = input("\nSelect an option: ")
            
            if choice == '1':
                paths = input("Enter paths to encrypt (separated by spaces): ").split()
                if not paths:
                    print("No paths entered")
                    continue
                
                password = getpass("Enter encryption password: ")
                confirm = getpass("Confirm password: ")
                
                if password != confirm:
                    print("Passwords do not match!")
                    continue
                
                self.process_files('encrypt', paths, password)
            
            elif choice == '2':
                paths = input("Enter paths to encrypted files (separated by spaces): ").split()
                if not paths:
                    print("No paths entered")
                    continue
                
                password = getpass("Enter decryption password: ")
                self.process_files('decrypt', paths, password)
            
            elif choice == '3':
                self.configure()
            
            elif choice == '4':
                print("Goodbye!")
                break
            
            else:
                print("Invalid option")

if __name__ == "__main__":
    tool = AdvancedEncryptionTool()
    tool.run()