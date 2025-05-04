import importlib
import subprocess
import sys
import time
import os

# *KABOOM!* Anubis guards the vault, checking for our sacred tools!
def check_dependencies() -> None:
    dependencies = {'cryptography': 'cryptography', 'stegano': 'stegano', 'Pillow': 'PIL', 'colorama': 'colorama'}
    missing = []
    
    for name, module in dependencies.items():
        try:
            importlib.import_module(module)
        except ImportError:
            missing.append(name)
    
    if not missing:
        print("All artifacts ready! Anubis approves!")
        return
    
    print(f"Holy missing relics, Pharaoh! We need: {', '.join(missing)}")
    install = input("Shall I summon them with pip? (y/n): ").lower()
    if install != 'y':
        print("No worries! Fetch them yourself with:")
        print("  pip install cryptography stegano Pillow colorama")
        print("Then return to the vault!")
        sys.exit(1)
    
    print("Hold onto your ankh, summoning...")
    for dep in missing:
        try:
            subprocess.run([sys.executable, '-m', 'pip', 'install', dep], check=True)
            print(f"{dep} is enshrined in the vault!")
        except subprocess.CalledProcessError:
            print(f"Oof, {dep} resisted the summons. Try this:")
            print(f"  pip install {dep}")
            print("Check your pip or permissions, guardian!")
            sys.exit(1)
    
    print("All relics secured! Let’s open the vault!")
    try:
        for name, module in dependencies.items():
            importlib.import_module(module)
    except ImportError:
        print("Something’s still cursed. Install manually:")
        print("  pip install cryptography stegano Pillow colorama")
        sys.exit(1)

# *BZZT!* Ensuring our tools are ready before Anubis opens the vault!
check_dependencies()

if __name__ == "__main__":
    import json
    import gzip
    import zipfile
    import hashlib
    import secrets
    import base64
    import math
    from datetime import datetime
    from pathlib import Path
    from typing import Optional, List, Tuple
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes, padding
    from cryptography.hazmat.backends import default_backend
    from getpass import getpass
    from PIL import Image
    import shutil
    from stegano import lsb
    from colorama import init, Fore, Style

    # *FLASH!* Setting up our colorful hieroglyphs!
    init()

    # *SPIN!* Simple spinner to show Anubis is at work!
    def spinner(message: str, duration: float = 1.0) -> None:
        spinner_chars = '|/-\\'
        for _ in range(int(duration * 4)):
            for char in spinner_chars:
                print(f"\r{Fore.YELLOW}{message} {char}{Style.RESET_ALL}", end="")
                time.sleep(0.1)
        print("\r" + " " * (len(message) + 2), end="\r")

    class EncryptionConfig:
        # Yo, I'm the scribe, recording Anubis’ sacred vault settings!
        DEFAULT_CONFIG = {
            "salt_length": 32,
            "iv_length": 16,
            "key_length": 32,
            "iterations": 500000,
            "compression_level": 9,
            "output_dir": "secure_files",
            "temp_dir": ".temp",
            "stego_dir": "secure_files/stego",
            "hash_algorithm": "sha256",
            "cleanup_temp": True
        }

        def __init__(self, config_file: str = "anubis_config.json"):
            self.config_file = config_file
            self.config = self.DEFAULT_CONFIG.copy()
            self.load_config()

        # *SLURP!* Inscribing the config scroll, ignoring those chatty _comments.
        def load_config(self) -> None:
            try:
                if os.path.exists(self.config_file):
                    with open(self.config_file, 'r') as f:
                        data = json.load(f)
                        self._comments = data.pop('_comments', {})
                        self.config.update(data)
            except Exception as e:
                print(f"{Fore.RED}🚫 Config scroll cursed: {e}{Style.RESET_ALL}")

        # *SPLAT!* Etching the config onto the vault walls!
        def save_config(self) -> bool:
            try:
                with open(self.config_file, 'w') as f:
                    data = self.config.copy()
                    data['_comments'] = self._comments
                    json.dump(data, f, indent=4)
                return True
            except Exception as e:
                print(f"{Fore.RED}🚫 Couldn't etch config: {e}{Style.RESET_ALL}")
                return False

        def get(self, key: str):
            return self.config.get(key, self.DEFAULT_CONFIG.get(key))

        def set(self, key: str, value) -> None:
            if key in self.DEFAULT_CONFIG:
                self.config[key] = value
            else:
                raise ValueError(f"Unknown config key: {key}")

    class FileCompressor:
        # I'm the embalmer, mummifying files for the vault!
        def __init__(self, config: EncryptionConfig):
            self.config = config
            self._setup_temp_dir()

        def _setup_temp_dir(self) -> None:
            os.makedirs(self.config.get('temp_dir'), exist_ok=True)

        # *CRUNCH!* Wrapping your file in sacred bandages!
        def compress(self, input_path: str, output_zip: str) -> bool:
            try:
                spinner("Mummifying file...")
                temp_gzip = Path(self.config.get('temp_dir')) / f"{Path(input_path).name}.gz"
                with open(input_path, 'rb') as in_file, gzip.open(temp_gzip, 'wb', compresslevel=9) as gz_file:
                    shutil.copyfileobj(in_file, gz_file)
                
                with zipfile.ZipFile(output_zip, 'w', zipfile.ZIP_DEFLATED, 
                                   compresslevel=self.config.get('compression_level')) as zipf:
                    zipf.write(temp_gzip, f"{Path(input_path).name}.gz")
                
                with zipfile.ZipFile(output_zip, 'r') as zipf:
                    if zipf.testzip() is not None:
                        raise zipfile.BadZipFile("Sarcophagus corrupted!")
                return True
            except Exception as e:
                print(f"{Fore.RED}🚫 Mummification failed: {e}{Style.RESET_ALL}")
                return False
            finally:
                temp_gzip.unlink(missing_ok=True)

        def _detect_file_type(self, file_path: str) -> str:
            try:
                with open(file_path, 'rb') as f:
                    header = f.read(8)
                if header.startswith(b'%PDF'):
                    return '.pdf'
                elif header.startswith(b'\x89PNG'):
                    return '.png'
                elif header.startswith(b'\xFF\xD8\xFF'):
                    return '.jpg'
                elif header.startswith(b'PK\x03\x04'):
                    try:
                        with zipfile.ZipFile(file_path, 'r') as zipf:
                            file_list = zipf.namelist()
                            if any('[Content_Types].xml' in f or 'word/' in f for f in file_list):
                                return '.docx'
                        return '.zip'
                    except zipfile.BadZipFile:
                        return '.bin'
                with open(file_path, 'rb') as f:
                    content = f.read(1024)
                    try:
                        content.decode('ascii')
                        if all(c < 128 and (c >= 32 or c in b'\n\r\t') for c in content):
                            return '.txt'
                    except UnicodeDecodeError:
                        pass
                return '.bin'
            except Exception:
                print(f"{Fore.RED}🚫 Scroll type unknown, assuming .bin!{Style.RESET_ALL}")
                return '.bin'

        # *POP!* Unwrapping your file from its sacred bandages!
        def decompress(self, zip_path: str, output_path: str) -> Tuple[bool, str]:
            try:
                spinner("Unwrapping file...")
                temp_extract = Path(self.config.get('temp_dir')) / 'extracted'
                os.makedirs(temp_extract, exist_ok=True)
                
                with zipfile.ZipFile(zip_path, 'r') as zipf:
                    zipf.extractall(temp_extract)
                
                gz_files = list(temp_extract.glob('*.gz'))
                if not gz_files:
                    print(f"{Fore.RED}🚫 No .gz scroll in the sarcophagus!{Style.RESET_ALL}")
                    return False, ''
                
                temp_output = temp_extract / 'temp_decompressed'
                with gzip.open(gz_files[0], 'rb') as gz_file, open(temp_output, 'wb') as out_file:
                    shutil.copyfileobj(gz_file, out_file)
                
                extension = self._detect_file_type(temp_output)
                
                shutil.move(temp_output, output_path)
                
                if not os.path.exists(output_path):
                    print(f"{Fore.RED}🚫 Scroll vanished: {output_path}{Style.RESET_ALL}")
                    return False, ''
                
                return True, extension
            except Exception as e:
                print(f"{Fore.RED}🚫 Unwrapping failed: {e}{Style.RESET_ALL}")
                return False, ''
            finally:
                if temp_extract.exists():
                    shutil.rmtree(temp_extract, ignore_errors=True)

    class AESEncryptor:
        # I'm the sentinel, sealing files with Anubis’ sacred AES-256!
        def __init__(self, config: EncryptionConfig):
            self.config = config

        def _derive_key(self, password: str, salt: bytes) -> bytes:
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=self.config.get('key_length'),
                salt=salt,
                iterations=self.config.get('iterations'),
                backend=default_backend()
            )
            return kdf.derive(password.encode())

        def _calculate_hash(self, file_path: str) -> str:
            hash_func = getattr(hashlib, self.config.get('hash_algorithm'))()
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b''):
                    hash_func.update(chunk)
            return hash_func.hexdigest()

        def _sanitize_filename(self, filename: str) -> str:
            filename = os.path.basename(filename)
            invalid_chars = '<>:"/\\|?*\0'
            for char in invalid_chars:
                filename = filename.replace(char, '_')
            return filename

        # *ZAP!* Sealing your file in the Anubis Vault!
        def encrypt(self, input_path: str, password: str, output_dir: Path) -> Optional[str]:
            try:
                spinner("Sealing scroll...")
                salt = secrets.token_bytes(self.config.get('salt_length'))
                iv = secrets.token_bytes(self.config.get('iv_length'))
                input_hash = self._calculate_hash(input_path)
                key = self._derive_key(password, salt)
                
                output_path = output_dir / f"{Path(input_path).name}.enc"
                cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
                encryptor = cipher.encryptor()
                padder = padding.PKCS7(128).padder()
                
                with open(input_path, 'rb') as in_file, open(output_path, 'wb') as out_file:
                    out_file.write(salt)
                    out_file.write(iv)
                    out_file.write(input_hash.encode())
                    while True:
                        chunk = in_file.read(8192)
                        if not chunk:
                            break
                        padded_chunk = padder.update(chunk)
                        out_file.write(encryptor.update(padded_chunk))
                    padded_chunk = padder.finalize()
                    out_file.write(encryptor.update(padded_chunk) + encryptor.finalize())
                
                return str(output_path)
            except Exception as e:
                print(f"{Fore.RED}🚫 Sealing failed: {e}{Style.RESET_ALL}")
                return None

        # *BOOM!* Releasing your file from the Anubis Vault!
        def decrypt(self, input_path: str, password: str, output_dir: Path) -> Optional[str]:
            try:
                spinner("Unlocking vault...")
                with open(input_path, 'rb') as f:
                    salt = f.read(self.config.get('salt_length'))
                    iv = f.read(self.config.get('iv_length'))
                    stored_hash = f.read(64).decode()
                    key = self._derive_key(password, salt)
                    
                    output_path = output_dir / Path(input_path).stem
                    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
                    decryptor = cipher.decryptor()
                    unpadder = padding.PKCS7(128).unpadder()
                    
                    with open(output_path, 'wb') as out_file:
                        while True:
                            chunk = f.read(8192)
                            if not chunk:
                                break
                            decrypted_chunk = decryptor.update(chunk)
                            try:
                                if not f.peek(1):
                                    decrypted_chunk = unpadder.update(decrypted_chunk) + unpadder.finalize()
                                else:
                                    decrypted_chunk = unpadder.update(decrypted_chunk)
                                out_file.write(decrypted_chunk)
                            except ValueError as e:
                                output_path.unlink(missing_ok=True)
                                print(f"{Fore.RED}🚫 Wrong key or cursed file: {e}{Style.RESET_ALL}")
                                return None
                    
                    calculated_hash = self._calculate_hash(output_path)
                    if calculated_hash != stored_hash:
                        output_path.unlink(missing_ok=True)
                        print(f"{Fore.RED}🚫 Scroll tampered! Expected {stored_hash}, got {calculated_hash}{Style.RESET_ALL}")
                        return None
                    
                    return str(output_path)
            except Exception as e:
                print(f"{Fore.RED}🚫 Vault unlock failed: {e}{Style.RESET_ALL}")
                return None
            finally:
                if 'output_path' in locals() and os.path.exists(output_path):
                    if not os.path.getsize(output_path):
                        output_path.unlink(missing_ok=True)

    class StegoHandler:
        # I'm the shadow scribe, hiding secrets in hieroglyphs!
        SUPPORTED_FORMATS = {'.png', '.jpg', '.jpeg', '.bmp', '.gif', '.tiff', '.webp'}

        def __init__(self, config: EncryptionConfig):
            self.config = config
            self._setup_stego_dir()

        def _setup_stego_dir(self) -> None:
            os.makedirs(self.config.get('stego_dir'), exist_ok=True)

        def _calculate_hash(self, data: bytes) -> str:
            hash_func = hashlib.sha256()
            hash_func.update(data)
            return hash_func.hexdigest()

        def _estimate_required_dimensions(self, data_size: int) -> str:
            pixels_needed = data_size * 8
            side = int(math.ceil(math.sqrt(pixels_needed)))
            return f"{side}x{side}"

        # *BAM!* Concealing your scroll in a sacred sarcophagus!
        def hide(self, data_path: str, carrier_image: str, validator: callable) -> Optional[str]:
            while True:
                try:
                    carrier_image = validator(carrier_image, is_carrier=True)
                    if not carrier_image:
                        return None
                    
                    input_ext = Path(carrier_image).suffix.lower()
                    if input_ext not in self.SUPPORTED_FORMATS:
                        print(f"{Fore.RED}🚫 Invalid sarcophagus format {input_ext}. Use {', '.join(self.SUPPORTED_FORMATS)}!{Style.RESET_ALL}")
                        return None
                    
                    spinner("Crafting hieroglyphs...")
                    temp_carrier = Path(self.config.get('temp_dir')) / 'temp_sarcophagus.png'
                    with Image.open(carrier_image) as img:
                        if img.mode != 'RGB':
                            img = img.convert('RGB')
                        img.save(temp_carrier, 'PNG', compress_level=9, optimize=True)
                    
                    with open(data_path, 'rb') as f:
                        data = f.read()
                    data_hash = self._calculate_hash(data)
                    data_size = len(data)
                    encoded_data = base64.b64encode(data).decode('utf-8')
                    encoded_size = len(encoded_data)
                    print(f"{Fore.YELLOW}Concealing {data_path} ({data_size} bytes, hash: {data_hash}){Style.RESET_ALL}")
                    
                    carrier_size = os.path.getsize(temp_carrier)
                    max_stego_size = carrier_size * 1.2
                    with Image.open(temp_carrier) as img:
                        width, height = img.size
                        max_capacity = width * height // 8
                        if encoded_size > max_capacity:
                            required_dims = self._estimate_required_dimensions(encoded_size)
                            print(f"{Fore.YELLOW}⚠️ Sarcophagus too small! Need {encoded_size} bytes, got {max_capacity}{Style.RESET_ALL}")
                            print(f"{Fore.YELLOW}Use a larger image, like {required_dims} pixels!{Style.RESET_ALL}")
                            retry = input(f"{Fore.CYAN}Try a new sarcophagus? (y/n): {Style.RESET_ALL}").lower()
                            if retry == 'y':
                                carrier_image = input(f"{Fore.CYAN}Enter image path (e.g., /path/to/sarcophagus.png): {Style.RESET_ALL}")
                                continue
                            else:
                                print(f"{Fore.YELLOW}No concealment, but your scroll’s safe at: {data_path}{Style.RESET_ALL}")
                                return None
                        if encoded_size + carrier_size > max_stego_size:
                            print(f"{Fore.RED}🚫 Hieroglyphs too large. Use a smaller scroll!{Style.RESET_ALL}")
                            return None
                    
                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                    output_dir = Path(self.config.get('stego_dir')) / timestamp
                    os.makedirs(output_dir, exist_ok=True)
                    output_path = output_dir / f"{Path(carrier_image).stem}.png"
                    
                    stego_img = lsb.hide(str(temp_carrier), encoded_data)
                    stego_img.save(output_path, 'PNG', compress_level=9, optimize=True)
                    
                    print(f"{Fore.GREEN}✅ *BAM!* Concealed in the sarcophagus: {output_path} ({os.path.getsize(output_path)} bytes){Style.RESET_ALL}")
                    return str(output_path)
                except Exception as e:
                    print(f"{Fore.RED}🚫 Concealment failed: {e}{Style.RESET_ALL}")
                    return None
                finally:
                    temp_carrier.unlink(missing_ok=True)

        # *WHOOSH!* Unveiling your scroll from its hieroglyphs!
        def extract(self, image_path: str, output_path: str) -> bool:
            try:
                spinner("Deciphering hieroglyphs...")
                ext = Path(image_path).suffix.lower()
                if ext not in {'.png'}:
                    print(f"{Fore.RED}🚫 Only PNG sarcophagi for extraction!{Style.RESET_ALL}")
                    return False
                
                encoded_data = lsb.reveal(image_path)
                if encoded_data is None:
                    print(f"{Fore.RED}🚫 No secrets in this sarcophagus!{Style.RESET_ALL}")
                    return False
                
                if isinstance(encoded_data, bytes):
                    encoded_data = encoded_data.decode('utf-8')
                elif not isinstance(encoded_data, str):
                    print(f"{Fore.RED}🚫 Strange hieroglyphs detected!{Style.RESET_ALL}")
                    return False
                
                try:
                    data = base64.b64decode(encoded_data)
                except Exception as e:
                    print(f"{Fore.RED}🚫 Hieroglyphs unreadable: {e}{Style.RESET_ALL}")
                    return False
                
                data_size = len(data)
                data_hash = self._calculate_hash(data)
                with open(output_path, 'wb') as f:
                    f.write(data)
                print(f"{Fore.GREEN}✅ *WHOOSH!* Unveiled {data_size} bytes to {output_path} (hash: {data_hash}){Style.RESET_ALL}")
                return True
            except Exception as e:
                print(f"{Fore.RED}🚫 Deciphering failed: {e}{Style.RESET_ALL}")
                return False

    class EncryptionTool:
        # I'm Anubis, guardian of the vault, overseeing all sacred rites!
        def __init__(self):
            self.config = EncryptionConfig()
            self.compressor = FileCompressor(self.config)
            self.encryptor = AESEncryptor(self.config)
            self.stego = StegoHandler(self.config)

        def _create_output_dir(self, operation: str) -> Path:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_dir = Path(self.config.get('output_dir')) / operation / timestamp
            os.makedirs(output_dir, exist_ok=True)
            return output_dir

        def _validate_path(self, path: str, is_input: bool = True, is_carrier: bool = False) -> Optional[str]:
            if not path or path.lower() == 'q':
                print(f"{Fore.YELLOW}⚠️ Ritual cancelled!{Style.RESET_ALL}")
                return None
            path = path.strip()
            path = os.path.expanduser(path)
            if not (path.startswith('/') or path.startswith(os.path.expanduser('~'))):
                print(f"{Fore.RED}🚫 Relative path? Use absolute like /path/to/scroll!{Style.RESET_ALL}")
                return None
            if not os.path.exists(path):
                print(f"{Fore.RED}🚫 Scroll’s lost in the sands: {path}{Style.RESET_ALL}")
                return None
            if is_input and not os.path.isfile(path):
                print(f"{Fore.RED}🚫 Need a scroll, not a tomb: {path}{Style.RESET_ALL}")
                return None
            if is_input and not os.access(path, os.R_OK):
                print(f"{Fore.RED}🚫 Can’t read this scroll: {path}{Style.RESET_ALL}")
                return None
            if is_carrier and Path(path).suffix.lower() not in self.stego.SUPPORTED_FORMATS:
                print(f"{Fore.RED}🚫 Wrong sarcophagus type {Path(path).suffix}. Use {', '.join(self.stego.SUPPORTED_FORMATS)}!{Style.RESET_ALL}")
                return None
            return path

        # *KA-POW!* Sealing your scroll in the Anubis Vault!
        def encrypt_file(self, input_path: str, password: str) -> bool:
            temp_zip = None
            try:
                input_path = self._validate_path(input_path)
                if not input_path:
                    return False
                
                print(f"{Fore.BLUE}--- Mummifying ---{Style.RESET_ALL}")
                temp_zip = Path(self.config.get('temp_dir')) / f"{Path(input_path).name}.zip"
                if not self.compressor.compress(input_path, str(temp_zip)):
                    return False
                print(f"{Fore.GREEN}✅ Mummified: {input_path} -> {temp_zip} ({os.path.getsize(temp_zip)} bytes){Style.RESET_ALL}")
                
                print(f"{Fore.BLUE}--- Sealing ---{Style.RESET_ALL}")
                output_dir = self._create_output_dir('encrypted')
                enc_path = self.encryptor.encrypt(str(temp_zip), password, output_dir)
                if not enc_path:
                    return False
                print(f"{Fore.GREEN}✅ *ZAP!* Sealed in the Anubis Vault: {input_path} -> {enc_path}{Style.RESET_ALL}")
                
                print(f"{Fore.BLUE}--- Concealment ---{Style.RESET_ALL}")
                hide = input(f"{Fore.CYAN}Hide in a sarcophagus? (y/n, needs a large PNG like 1920x1080): {Style.RESET_ALL}").lower()
                if hide == 'y':
                    carrier_image = input(f"{Fore.CYAN}Enter sarcophagus path (e.g., /path/to/sarcophagus.png, q to cancel): {Style.RESET_ALL}")
                    stego_path = self.stego.hide(enc_path, carrier_image, self._validate_path)
                    if stego_path:
                        print(f"{Fore.GREEN}✅ *BAM!* Concealed in the sarcophagus: {stego_path}{Style.RESET_ALL}")
                    else:
                        print(f"{Fore.YELLOW}⚠️ No concealment, but your scroll’s safe at: {enc_path}{Style.RESET_ALL}")
                
                print(f"{Fore.GREEN}🎉 Success! Your sealed scroll is at: {enc_path}{Style.RESET_ALL}")
                return True
            except Exception as e:
                print(f"{Fore.RED}🚫 Sealing ritual failed: {e}{Style.RESET_ALL}")
                return False
            finally:
                if temp_zip is not None:
                    temp_zip.unlink(missing_ok=True)
                if self.config.get('cleanup_temp'):
                    shutil.rmtree(self.config.get('temp_dir'), ignore_errors=True)
                    os.makedirs(self.config.get('temp_dir'))

        # *WHAM!* Releasing your scroll from the Anubis Vault!
        def decrypt_file(self, input_path: str, password: str) -> bool:
            zip_path = None
            temp_output = None
            try:
                input_path = self._validate_path(input_path)
                if not input_path:
                    return False
                
                actual_input = input_path
                is_stego = input_path.endswith('.png')
                if is_stego:
                    print(f"{Fore.BLUE}--- Deciphering Sarcophagus ---{Style.RESET_ALL}")
                    temp_enc = Path(self.config.get('temp_dir')) / 'extracted.enc'
                    if not self.stego.extract(input_path, str(temp_enc)):
                        return False
                    actual_input = str(temp_enc)
                
                print(f"{Fore.BLUE}--- Unlocking ---{Style.RESET_ALL}")
                output_dir = self._create_output_dir('decrypted')
                zip_path = self.encryptor.decrypt(actual_input, password, output_dir)
                if not zip_path:
                    return False
                print(f"{Fore.GREEN}✅ *BOOM!* Unlocked: {actual_input} -> {zip_path} ({os.path.getsize(zip_path)} bytes){Style.RESET_ALL}")
                
                if is_stego:
                    original_name = input(f"{Fore.CYAN}Original scroll name (no extension, e.g., papyrus, q to cancel): {Style.RESET_ALL}")
                    if not original_name or original_name.lower() == 'q':
                        print(f"{Fore.YELLOW}⚠️ Ritual cancelled!{Style.RESET_ALL}")
                        return False
                    original_name = self.encryptor._sanitize_filename(original_name)
                    original_name = Path(original_name).stem
                else:
                    original_name = Path(Path(input_path).stem).stem
                
                print(f"{Fore.BLUE}--- Unwrapping ---{Style.RESET_ALL}")
                temp_output = output_dir / f"{original_name}_temp"
                success, extension = self.compressor.decompress(zip_path, str(temp_output))
                if not success:
                    return False
                
                final_output = output_dir / f"{original_name}{extension}"
                if temp_output.exists():
                    shutil.move(temp_output, final_output)
                
                if not final_output.exists():
                    print(f"{Fore.RED}🚫 Scroll vanished: {final_output}{Style.RESET_ALL}")
                    return False
                print(f"{Fore.GREEN}✅ *WHAM!* Released from the Anubis Vault: {input_path} -> {final_output} ({os.path.getsize(final_output)} bytes){Style.RESET_ALL}")
                print(f"{Fore.GREEN}🎉 Success! Your scroll is at: {final_output}{Style.RESET_ALL}")
                return True
            except Exception as e:
                print(f"{Fore.RED}🚫 Unlocking ritual failed: {e}{Style.RESET_ALL}")
                return False
            finally:
                if is_stego and os.path.exists(actual_input):
                    os.unlink(actual_input)
                if zip_path is not None:
                    Path(zip_path).unlink(missing_ok=True)
                if temp_output is not None:
                    temp_output.unlink(missing_ok=True)
                if self.config.get('cleanup_temp'):
                    shutil.rmtree(self.config.get('temp_dir'), ignore_errors=True)
                    os.makedirs(self.config.get('temp_dir'))

        # *TWEAK!* Carving new runes into Anubis’ vault!
        def configure(self) -> None:
            print(f"{Fore.BLUE}=== Rune Carving Chamber 🛠️ ==={Style.RESET_ALL}")
            print(f"{Fore.YELLOW}Current runes (hit Enter to keep, q to exit):{Style.RESET_ALL}")
            
            try:
                for key in self.config.config:
                    comment = self.config._comments.get(key, "No inscription available.")
                    print(f"\n{Fore.BLUE}--- {key} ---{Style.RESET_ALL}")
                    print(f"{Fore.YELLOW}Inscription: {comment}{Style.RESET_ALL}")
                    print(f"{Fore.YELLOW}Current: {self.config.get(key)}{Style.RESET_ALL}")
                    value = input(f"{Fore.CYAN}New rune: {Style.RESET_ALL}")
                    if value.lower() == 'q':
                        print(f"{Fore.YELLOW}⚠️ Rune carving cancelled!{Style.RESET_ALL}")
                        return
                    if value:
                        if key in ['iterations', 'salt_length', 'iv_length', 'key_length']:
                            if not value.isdigit():
                                print(f"{Fore.RED}🚫 Must be a number!{Style.RESET_ALL}")
                                continue
                            value = int(value)
                        elif key == 'compression_level':
                            if not value.isdigit() or not 1 <= int(value) <= 9:
                                print(f"{Fore.RED}🚫 Must be 1–9!{Style.RESET_ALL}")
                                continue
                            value = int(value)
                        elif key == 'cleanup_temp':
                            if value.lower() not in ['true', 'false']:
                                print(f"{Fore.RED}🚫 Must be true/false!{Style.RESET_ALL}")
                                continue
                            value = value.lower() == 'true'
                        self.config.set(key, value)
                
                if self.config.save_config():
                    print(f"{Fore.GREEN}✅ Runes carved! Anubis is pleased!{Style.RESET_ALL}")
                else:
                    print(f"{Fore.RED}🚫 Rune carving failed. Curse the sands!{Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.RED}🚫 Rune carving disrupted: {e}{Style.RESET_ALL}")

        # *BZZT!* The grand ritual, where Anubis guides your path!
        def run(self) -> None:
            while True:
                os.system('clear' if os.name == 'posix' else 'cls')
                print(f"{Fore.BLUE}=============================={Style.RESET_ALL}")
                print(f"{Fore.BLUE}        Anubis Vault          {Style.RESET_ALL}")
                print(f"{Fore.BLUE}Protected by the Guardian of Secrets!{Style.RESET_ALL}")
                print(f"{Fore.BLUE}=============================={Style.RESET_ALL}")
                print(f"  {Fore.CYAN}[1] Seal Scroll{Style.RESET_ALL}")
                print(f"  {Fore.CYAN}[2] Release Scroll{Style.RESET_ALL}")
                print(f"  {Fore.CYAN}[3] Carve Runes{Style.RESET_ALL}")
                print(f"  {Fore.CYAN}[4] Depart{Style.RESET_ALL}")
                print(f"{Fore.BLUE}------------------------------{Style.RESET_ALL}")
                
                choice = input(f"{Fore.CYAN}Choose your ritual: {Style.RESET_ALL}").strip()
                
                if choice == '1':
                    print(f"{Fore.BLUE}=== Sealing Ritual ==={Style.RESET_ALL}")
                    print(f"{Fore.BLUE}--- Scroll Selection ---{Style.RESET_ALL}")
                    valid_paths = []
                    while True:
                        path = input(f"{Fore.CYAN}Scroll to seal (absolute path like /path/to/secret_scroll.txt, q to cancel): {Style.RESET_ALL}")
                        validated_path = self._validate_path(path)
                        if validated_path:
                            valid_paths.append(validated_path)
                        elif path.lower() == 'q':
                            break
                        add_another = input(f"{Fore.CYAN}Add another scroll? (y/n): {Style.RESET_ALL}").lower()
                        if add_another != 'y':
                            break
                    if not valid_paths:
                        print(f"{Fore.YELLOW}⚠️ No scrolls chosen. Back to the chamber!{Style.RESET_ALL}")
                        input(f"{Fore.CYAN}Press Enter to continue...{Style.RESET_ALL}")
                        continue
                    print(f"{Fore.YELLOW}Chosen scrolls: {', '.join(valid_paths)}{Style.RESET_ALL}")
                    print(f"{Fore.BLUE}--- Sacred Oath ---{Style.RESET_ALL}")
                    print(f"{Fore.YELLOW}💡 Use 12+ chars with letters, numbers, symbols!{Style.RESET_ALL}")
                    password = getpass(f"{Fore.CYAN}Oath: {Style.RESET_ALL}")
                    confirm = getpass(f"{Fore.CYAN}Confirm oath: {Style.RESET_ALL}")
                    os.system('clear' if os.name == 'posix' else 'cls')
                    if password != confirm:
                        print(f"{Fore.RED}🚫 Oaths don’t match. Swear again, guardian!{Style.RESET_ALL}")
                        input(f"{Fore.CYAN}Press Enter to continue...{Style.RESET_ALL}")
                        continue
                    for path in valid_paths:
                        self.encrypt_file(path, password)
                    input(f"{Fore.CYAN}Press Enter to continue...{Style.RESET_ALL}")
                
                elif choice == '2':
                    print(f"{Fore.BLUE}=== Release Ritual ==={Style.RESET_ALL}")
                    print(f"{Fore.BLUE}--- Scroll Selection ---{Style.RESET_ALL}")
                    valid_paths = []
                    while True:
                        path = input(f"{Fore.CYAN}Scroll to release (.enc or .png, absolute path like /path/to/scroll, q to cancel): {Style.RESET_ALL}")
                        validated_path = self._validate_path(path)
                        if validated_path:
                            valid_paths.append(validated_path)
                        elif path.lower() == 'q':
                            break
                        add_another = input(f"{Fore.CYAN}Add another scroll? (y/n): {Style.RESET_ALL}").lower()
                        if add_another != 'y':
                            break
                    if not valid_paths:
                        print(f"{Fore.YELLOW}⚠️ No scrolls chosen. Back to the chamber!{Style.RESET_ALL}")
                        input(f"{Fore.CYAN}Press Enter to continue...{Style.RESET_ALL}")
                        continue
                    print(f"{Fore.YELLOW}Chosen scrolls: {', '.join(valid_paths)}{Style.RESET_ALL}")
                    print(f"{Fore.BLUE}--- Sacred Oath ---{Style.RESET_ALL}")
                    password = getpass(f"{Fore.CYAN}Oath: {Style.RESET_ALL}")
                    os.system('clear' if os.name == 'posix' else 'cls')
                    for path in valid_paths:
                        self.decrypt_file(path, password)
                    input(f"{Fore.CYAN}Press Enter to continue...{Style.RESET_ALL}")
                
                elif choice == '3':
                    self.configure()
                    input(f"{Fore.CYAN}Press Enter to continue...{Style.RESET_ALL}")
                
                elif choice == '4':
                    print(f"{Fore.GREEN}🎉 Depart in peace! Anubis guards your secrets!{Style.RESET_ALL}")
                    break
                
                elif choice == '42':
                    print(f"{Fore.YELLOW}🌌 The Answer to Life, the Universe, and the Anubis Vault!{Style.RESET_ALL}")
                    input(f"{Fore.CYAN}Press Enter to continue...{Style.RESET_ALL}")
                
                else:
                    print(f"{Fore.RED}🚫 Invalid ritual. Choose a number, not a riddle!{Style.RESET_ALL}")
                    input(f"{Fore.CYAN}Press Enter to continue...{Style.RESET_ALL}")

    tool = EncryptionTool()
    tool.run()