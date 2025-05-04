import importlib
import subprocess
import sys
import time
import os

# *KABOOM!* Checking if we've got our superhero tools before we start!
def check_dependencies() -> None:
    dependencies = {'cryptography': 'cryptography', 'stegano': 'stegano', 'Pillow': 'PIL', 'colorama': 'colorama'}
    missing = []
    
    for name, module in dependencies.items():
        try:
            importlib.import_module(module)
        except ImportError:
            missing.append(name)
    
    if not missing:
        print("All gadgets ready! Time to save the day!")
        return
    
    print(f"Holy missing modules, Batman! We need: {', '.join(missing)}")
    install = input("Shall I fetch them with pip? (y/n): ").lower()
    if install != 'y':
        print("No prob! Grab 'em yourself with:")
        print("  pip install cryptography stegano Pillow colorama")
        print("Then call me back!")
        sys.exit(1)
    
    print("Hold onto your cape, installing...")
    for dep in missing:
        try:
            subprocess.run([sys.executable, '-m', 'pip', 'install', dep], check=True)
            print(f"{dep} is locked and loaded!")
        except subprocess.CalledProcessError:
            print(f"Oof, {dep} didn't install. Try this:")
            print(f"  pip install {dep}")
            print("Check your pip or permissions, hero!")
            sys.exit(1)
    
    print("All systems go! Let’s do this!")
    try:
        for name, module in dependencies.items():
            importlib.import_module(module)
    except ImportError:
        print("Something’s still funky. Install manually:")
        print("  pip install cryptography stegano Pillow colorama")
        sys.exit(1)

# *BZZT!* Make sure we’ve got our tools before we load the big guns!
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

    # *FLASH!* Setting up our colorful console magic!
    init()

    # *SPIN!* Simple spinner to show we’re working hard!
    def spinner(message: str, duration: float = 1.0) -> None:
        spinner_chars = '|/-\\'
        for _ in range(int(duration * 4)):
            for char in spinner_chars:
                print(f"\r{Fore.YELLOW}{message} {char}{Style.RESET_ALL}", end="")
                time.sleep(0.1)
        print("\r" + " " * (len(message) + 2), end="\r")

    class EncryptionConfig:
        # Yo, I'm the config boss, holding all the secrets for how we encrypt stuff!
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

        def __init__(self, config_file: str = "encryption_config.json"):
            self.config_file = config_file
            self.config = self.DEFAULT_CONFIG.copy()
            self.load_config()

        # *SLURP!* Sucking in the config file, but ignoring those chatty _comments.
        def load_config(self) -> None:
            try:
                if os.path.exists(self.config_file):
                    with open(self.config_file, 'r') as f:
                        data = json.load(f)
                        self._comments = data.pop('_comments', {})
                        self.config.update(data)
            except Exception as e:
                print(f"{Fore.RED}🚫 Config file threw a tantrum: {e}{Style.RESET_ALL}")

        # *SPLAT!* Spitting out the config to disk for next time.
        def save_config(self) -> bool:
            try:
                with open(self.config_file, 'w') as f:
                    data = self.config.copy()
                    data['_comments'] = self._comments
                    json.dump(data, f, indent=4)
                return True
            except Exception as e:
                print(f"{Fore.RED}🚫 Couldn't save config: {e}{Style.RESET_ALL}")
                return False

        def get(self, key: str):
            return self.config.get(key, self.DEFAULT_CONFIG.get(key))

        def set(self, key: str, value) -> None:
            if key in self.DEFAULT_CONFIG:
                self.config[key] = value
            else:
                raise ValueError(f"Unknown config key: {key}")

    class FileCompressor:
        # I'm the cruncher, squashing files so they fit snugly in our encryption vault!
        def __init__(self, config: EncryptionConfig):
            self.config = config
            self._setup_temp_dir()

        def _setup_temp_dir(self) -> None:
            os.makedirs(self.config.get('temp_dir'), exist_ok=True)

        # *CRUNCH!* Zipping your file into a tiny package, ready for encryption!
        def compress(self, input_path: str, output_zip: str) -> bool:
            try:
                spinner("Compressing file...")
                temp_gzip = Path(self.config.get('temp_dir')) / f"{Path(input_path).name}.gz"
                with open(input_path, 'rb') as in_file, gzip.open(temp_gzip, 'wb', compresslevel=9) as gz_file:
                    shutil.copyfileobj(in_file, gz_file)
                
                with zipfile.ZipFile(output_zip, 'w', zipfile.ZIP_DEFLATED, 
                                   compresslevel=self.config.get('compression_level')) as zipf:
                    zipf.write(temp_gzip, f"{Path(input_path).name}.gz")
                
                with zipfile.ZipFile(output_zip, 'r') as zipf:
                    if zipf.testzip() is not None:
                        raise zipfile.BadZipFile("ZIP went kaput!")
                return True
            except Exception as e:
                print(f"{Fore.RED}🚫 Compression flopped: {e}{Style.RESET_ALL}")
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
                print(f"{Fore.RED}🚫 File type? Beats me, going with .bin!{Style.RESET_ALL}")
                return '.bin'

        # *POP!* Unzipping your file back to its original glory!
        def decompress(self, zip_path: str, output_path: str) -> Tuple[bool, str]:
            try:
                spinner("Decompressing file...")
                temp_extract = Path(self.config.get('temp_dir')) / 'extracted'
                os.makedirs(temp_extract, exist_ok=True)
                
                with zipfile.ZipFile(zip_path, 'r') as zipf:
                    zipf.extractall(temp_extract)
                
                gz_files = list(temp_extract.glob('*.gz'))
                if not gz_files:
                    print(f"{Fore.RED}🚫 No .gz file in the ZIP. What’s going on?{Style.RESET_ALL}")
                    return False, ''
                
                temp_output = temp_extract / 'temp_decompressed'
                with gzip.open(gz_files[0], 'rb') as gz_file, open(temp_output, 'wb') as out_file:
                    shutil.copyfileobj(gz_file, out_file)
                
                extension = self._detect_file_type(temp_output)
                
                shutil.move(temp_output, output_path)
                
                if not os.path.exists(output_path):
                    print(f"{Fore.RED}🚫 Output file vanished: {output_path}{Style.RESET_ALL}")
                    return False, ''
                
                return True, extension
            except Exception as e:
                print(f"{Fore.RED}🚫 Decompression went poof: {e}{Style.RESET_ALL}")
                return False, ''
            finally:
                if temp_extract.exists():
                    shutil.rmtree(temp_extract, ignore_errors=True)

    class AESEncryptor:
        # I'm the vault, locking your files with AES-256 like a superhero!
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

        # *ZAP!* Locking your file in a super-secure .enc cage!
        def encrypt(self, input_path: str, password: str, output_dir: Path) -> Optional[str]:
            try:
                spinner("Encrypting file...")
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
                print(f"{Fore.RED}🚫 Encryption fizzled: {e}{Style.RESET_ALL}")
                return None

        # *BOOM!* Busting your file out of its .enc prison!
        def decrypt(self, input_path: str, password: str, output_dir: Path) -> Optional[str]:
            try:
                spinner("Decrypting file...")
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
                                print(f"{Fore.RED}🚫 Wrong key or busted file: {e}{Style.RESET_ALL}")
                                return None
                    
                    calculated_hash = self._calculate_hash(output_path)
                    if calculated_hash != stored_hash:
                        output_path.unlink(missing_ok=True)
                        print(f"{Fore.RED}🚫 File’s been tampered with! Expected {stored_hash}, got {calculated_hash}{Style.RESET_ALL}")
                        return None
                    
                    return str(output_path)
            except Exception as e:
                print(f"{Fore.RED}🚫 Decryption crashed: {e}{Style.RESET_ALL}")
                return None
            finally:
                if 'output_path' in locals() and os.path.exists(output_path):
                    if not os.path.getsize(output_path):
                        output_path.unlink(missing_ok=True)

    class StegoHandler:
        # I'm the sneaky ninja, hiding files in images like a comic book spy!
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

        # *BAM!* Hiding your file in a PNG like it’s wearing an invisibility cloak!
        def hide(self, data_path: str, carrier_image: str, validator: callable) -> Optional[str]:
            while True:
                try:
                    carrier_image = validator(carrier_image, is_carrier=True)
                    if not carrier_image:
                        return None
                    
                    input_ext = Path(carrier_image).suffix.lower()
                    if input_ext not in self.SUPPORTED_FORMATS:
                        print(f"{Fore.RED}🚫 Bad image format {input_ext}. Try {', '.join(self.SUPPORTED_FORMATS)}!{Style.RESET_ALL}")
                        return None
                    
                    spinner("Preparing stego image...")
                    temp_carrier = Path(self.config.get('temp_dir')) / 'temp_carrier.png'
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
                    print(f"{Fore.YELLOW}Hiding {data_path} ({data_size} bytes, hash: {data_hash}){Style.RESET_ALL}")
                    
                    carrier_size = os.path.getsize(temp_carrier)
                    max_stego_size = carrier_size * 1.2
                    with Image.open(temp_carrier) as img:
                        width, height = img.size
                        max_capacity = width * height // 8
                        if encoded_size > max_capacity:
                            required_dims = self._estimate_required_dimensions(encoded_size)
                            print(f"{Fore.YELLOW}⚠️ Image too tiny! Need {encoded_size} bytes, got {max_capacity}{Style.RESET_ALL}")
                            print(f"{Fore.YELLOW}Grab a bigger image, like {required_dims} pixels!{Style.RESET_ALL}")
                            retry = input(f"{Fore.CYAN}Try a new image? (y/n): {Style.RESET_ALL}").lower()
                            if retry == 'y':
                                carrier_image = input(f"{Fore.CYAN}Enter image path (e.g., /path/to/image.png): {Style.RESET_ALL}")
                                continue
                            else:
                                print(f"{Fore.YELLOW}No stego, but your file’s safe at: {data_path}{Style.RESET_ALL}")
                                return None
                        if encoded_size + carrier_size > max_stego_size:
                            print(f"{Fore.RED}🚫 Stego image would be HUGE. Try a smaller file!{Style.RESET_ALL}")
                            return None
                    
                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                    output_dir = Path(self.config.get('stego_dir')) / timestamp
                    os.makedirs(output_dir, exist_ok=True)
                    output_path = output_dir / f"{Path(carrier_image).stem}.png"
                    
                    stego_img = lsb.hide(str(temp_carrier), encoded_data)
                    stego_img.save(output_path, 'PNG', compress_level=9, optimize=True)
                    
                    print(f"{Fore.GREEN}✅ Stego image ready: {output_path} ({os.path.getsize(output_path)} bytes){Style.RESET_ALL}")
                    return str(output_path)
                except Exception as e:
                    print(f"{Fore.RED}🚫 Stego mission failed: {e}{Style.RESET_ALL}")
                    return None
                finally:
                    temp_carrier.unlink(missing_ok=True)

        # *WHOOSH!* Yanking your file out of its PNG hideout!
        def extract(self, image_path: str, output_path: str) -> bool:
            try:
                spinner("Extracting stego data...")
                ext = Path(image_path).suffix.lower()
                if ext not in {'.png'}:
                    print(f"{Fore.RED}🚫 Only PNGs for stego extraction, sorry!{Style.RESET_ALL}")
                    return False
                
                encoded_data = lsb.reveal(image_path)
                if encoded_data is None:
                    print(f"{Fore.RED}🚫 No secret data in this image. You sure it’s stego’d?{Style.RESET_ALL}")
                    return False
                
                if isinstance(encoded_data, bytes):
                    encoded_data = encoded_data.decode('utf-8')
                elif not isinstance(encoded_data, str):
                    print(f"{Fore.RED}🚫 Weird data in the image. Not our stuff!{Style.RESET_ALL}")
                    return False
                
                try:
                    data = base64.b64decode(encoded_data)
                except Exception as e:
                    print(f"{Fore.RED}🚫 Base64 decode went kablooey: {e}{Style.RESET_ALL}")
                    return False
                
                data_size = len(data)
                data_hash = self._calculate_hash(data)
                with open(output_path, 'wb') as f:
                    f.write(data)
                print(f"{Fore.GREEN}✅ Pulled {data_size} bytes to {output_path} (hash: {data_hash}){Style.RESET_ALL}")
                return True
            except Exception as e:
                print(f"{Fore.RED}🚫 Stego extraction flunked: {e}{Style.RESET_ALL}")
                return False

    class EncryptionTool:
        # I'm the mastermind, running the show for encryption, decryption, and sneaky stego!
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
                print(f"{Fore.YELLOW}⚠️ Cancelled!{Style.RESET_ALL}")
                return None
            path = path.strip()
            path = os.path.expanduser(path)
            if not (path.startswith('/') or path.startswith(os.path.expanduser('~'))):
                print(f"{Fore.RED}🚫 Relative path? Nah, use absolute like /path/to/file!{Style.RESET_ALL}")
                return None
            if not os.path.exists(path):
                print(f"{Fore.RED}🚫 Path’s playing hide-and-seek: {path}{Style.RESET_ALL}")
                return None
            if is_input and not os.path.isfile(path):
                print(f"{Fore.RED}🚫 Need a file, not a folder: {path}{Style.RESET_ALL}")
                return None
            if is_input and not os.access(path, os.R_OK):
                print(f"{Fore.RED}🚫 Can’t read this file: {path}{Style.RESET_ALL}")
                return None
            if is_carrier and Path(path).suffix.lower() not in self.stego.SUPPORTED_FORMATS:
                print(f"{Fore.RED}🚫 Wrong image type {Path(path).suffix}. Use {', '.join(self.stego.SUPPORTED_FORMATS)}!{Style.RESET_ALL}")
                return None
            return path

        # *KAPOW!* Encrypting your file and maybe hiding it in a PNG!
        def encrypt_file(self, input_path: str, password: str) -> bool:
            temp_zip = None
            try:
                input_path = self._validate_path(input_path)
                if not input_path:
                    return False
                
                print(f"{Fore.BLUE}--- Compressing ---{Style.RESET_ALL}")
                temp_zip = Path(self.config.get('temp_dir')) / f"{Path(input_path).name}.zip"
                if not self.compressor.compress(input_path, str(temp_zip)):
                    return False
                print(f"{Fore.GREEN}✅ Squashed: {input_path} -> {temp_zip} ({os.path.getsize(temp_zip)} bytes){Style.RESET_ALL}")
                
                print(f"{Fore.BLUE}--- Encrypting ---{Style.RESET_ALL}")
                output_dir = self._create_output_dir('encrypted')
                enc_path = self.encryptor.encrypt(str(temp_zip), password, output_dir)
                if not enc_path:
                    return False
                print(f"{Fore.GREEN}✅ *ZAP!* Locked tight: {input_path} -> {enc_path}{Style.RESET_ALL}")
                
                print(f"{Fore.BLUE}--- Steganography ---{Style.RESET_ALL}")
                hide = input(f"{Fore.CYAN}Hide in an image? (y/n, needs a big PNG like 1920x1080): {Style.RESET_ALL}").lower()
                if hide == 'y':
                    carrier_image = input(f"{Fore.CYAN}Enter image path (e.g., /path/to/image.png, q to cancel): {Style.RESET_ALL}")
                    stego_path = self.stego.hide(enc_path, carrier_image, self._validate_path)
                    if stego_path:
                        print(f"{Fore.GREEN}✅ *BAM!* Hidden like a ninja: {stego_path}{Style.RESET_ALL}")
                    else:
                        print(f"{Fore.YELLOW}⚠️ No stego, but your file’s safe at: {enc_path}{Style.RESET_ALL}")
                
                print(f"{Fore.GREEN}🎉 Success! Your encrypted file is at: {enc_path}{Style.RESET_ALL}")
                return True
            except Exception as e:
                print(f"{Fore.RED}🚫 Encryption went splat: {e}{Style.RESET_ALL}")
                return False
            finally:
                if temp_zip is not None:
                    temp_zip.unlink(missing_ok=True)
                if self.config.get('cleanup_temp'):
                    shutil.rmtree(self.config.get('temp_dir'), ignore_errors=True)
                    os.makedirs(self.config.get('temp_dir'))

        # *WHAM!* Freeing your file from its .enc or PNG cage!
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
                    print(f"{Fore.BLUE}--- Extracting Stego ---{Style.RESET_ALL}")
                    temp_enc = Path(self.config.get('temp_dir')) / 'extracted.enc'
                    if not self.stego.extract(input_path, str(temp_enc)):
                        return False
                    actual_input = str(temp_enc)
                
                print(f"{Fore.BLUE}--- Decrypting ---{Style.RESET_ALL}")
                output_dir = self._create_output_dir('decrypted')
                zip_path = self.encryptor.decrypt(actual_input, password, output_dir)
                if not zip_path:
                    return False
                print(f"{Fore.GREEN}✅ *BOOM!* Cracked open: {actual_input} -> {zip_path} ({os.path.getsize(zip_path)} bytes){Style.RESET_ALL}")
                
                if is_stego:
                    original_name = input(f"{Fore.CYAN}Original file name (no extension, e.g., example_file, q to cancel): {Style.RESET_ALL}")
                    if not original_name or original_name.lower() == 'q':
                        print(f"{Fore.YELLOW}⚠️ Cancelled!{Style.RESET_ALL}")
                        return False
                    original_name = self.encryptor._sanitize_filename(original_name)
                    original_name = Path(original_name).stem
                else:
                    original_name = Path(Path(input_path).stem).stem
                
                print(f"{Fore.BLUE}--- Decompressing ---{Style.RESET_ALL}")
                temp_output = output_dir / f"{original_name}_temp"
                success, extension = self.compressor.decompress(zip_path, str(temp_output))
                if not success:
                    return False
                
                final_output = output_dir / f"{original_name}{extension}"
                if temp_output.exists():
                    shutil.move(temp_output, final_output)
                
                if not final_output.exists():
                    print(f"{Fore.RED}🚫 Output file pulled a Houdini: {final_output}{Style.RESET_ALL}")
                    return False
                print(f"{Fore.GREEN}✅ *WHAM!* Freed: {input_path} -> {final_output} ({os.path.getsize(final_output)} bytes){Style.RESET_ALL}")
                print(f"{Fore.GREEN}🎉 Success! Your decrypted file is at: {final_output}{Style.RESET_ALL}")
                return True
            except Exception as e:
                print(f"{Fore.RED}🚫 Decryption tanked: {e}{Style.RESET_ALL}")
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

        # *TWEAK!* Letting you fiddle with the config like a mad scientist!
        def configure(self) -> None:
            print(f"{Fore.BLUE}=== Configuration Station 🛠️ ==={Style.RESET_ALL}")
            print(f"{Fore.YELLOW}Current settings (hit Enter to keep, q to exit):{Style.RESET_ALL}")
            
            try:
                for key in self.config.config:
                    comment = self.config._comments.get(key, "No description available.")
                    print(f"\n{Fore.BLUE}--- {key} ---{Style.RESET_ALL}")
                    print(f"{Fore.YELLOW}Description: {comment}{Style.RESET_ALL}")
                    print(f"{Fore.YELLOW}Current: {self.config.get(key)}{Style.RESET_ALL}")
                    value = input(f"{Fore.CYAN}New value: {Style.RESET_ALL}")
                    if value.lower() == 'q':
                        print(f"{Fore.YELLOW}⚠️ Config editing cancelled!{Style.RESET_ALL}")
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
                    print(f"{Fore.GREEN}✅ Config saved! You’re a genius!{Style.RESET_ALL}")
                else:
                    print(f"{Fore.RED}🚫 Config save failed. Blame the gremlins!{Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.RED}🚫 Config tweak went haywire: {e}{Style.RESET_ALL}")

        # *BZZT!* The main show, where you pick your encryption adventure!
        def run(self) -> None:
            while True:
                os.system('clear' if os.name == 'posix' else 'cls')
                print(f"{Fore.BLUE}=============================={Style.RESET_ALL}")
                print(f"{Fore.BLUE}    Advanced Encryption Tool  {Style.RESET_ALL}")
                print(f"{Fore.BLUE}  *ZAP!* Secure Files in a Snap!  {Style.RESET_ALL}")
                print(f"{Fore.BLUE}=============================={Style.RESET_ALL}")
                print(f"  {Fore.CYAN}[1] Encrypt File{Style.RESET_ALL}")
                print(f"  {Fore.CYAN}[2] Decrypt File{Style.RESET_ALL}")
                print(f"  {Fore.CYAN}[3] Configure Settings{Style.RESET_ALL}")
                print(f"  {Fore.CYAN}[4] Exit{Style.RESET_ALL}")
                print(f"{Fore.BLUE}------------------------------{Style.RESET_ALL}")
                
                choice = input(f"{Fore.CYAN}Pick your poison: {Style.RESET_ALL}").strip()
                
                if choice == '1':
                    print(f"{Fore.BLUE}=== Encryption Mission ==={Style.RESET_ALL}")
                    print(f"{Fore.BLUE}--- File Selection ---{Style.RESET_ALL}")
                    valid_paths = []
                    while True:
                        path = input(f"{Fore.CYAN}File to encrypt (absolute path like /path/to/file.pdf, q to cancel): {Style.RESET_ALL}")
                        validated_path = self._validate_path(path)
                        if validated_path:
                            valid_paths.append(validated_path)
                        elif path.lower() == 'q':
                            break
                        add_another = input(f"{Fore.CYAN}Add another file? (y/n): {Style.RESET_ALL}").lower()
                        if add_another != 'y':
                            break
                    if not valid_paths:
                        print(f"{Fore.YELLOW}⚠️ No files selected. Back to the menu!{Style.RESET_ALL}")
                        input(f"{Fore.CYAN}Press Enter to continue...{Style.RESET_ALL}")
                        continue
                    print(f"{Fore.YELLOW}Selected files: {', '.join(valid_paths)}{Style.RESET_ALL}")
                    print(f"{Fore.BLUE}--- Password ---{Style.RESET_ALL}")
                    print(f"{Fore.YELLOW}💡 Use 12+ chars with letters, numbers, symbols!{Style.RESET_ALL}")
                    password = getpass(f"{Fore.CYAN}Password: {Style.RESET_ALL}")
                    confirm = getpass(f"{Fore.CYAN}Confirm password: {Style.RESET_ALL}")
                    os.system('clear' if os.name == 'posix' else 'cls')
                    if password != confirm:
                        print(f"{Fore.RED}🚫 Passwords don’t match. Try again, champ!{Style.RESET_ALL}")
                        input(f"{Fore.CYAN}Press Enter to continue...{Style.RESET_ALL}")
                        continue
                    for path in valid_paths:
                        self.encrypt_file(path, password)
                    input(f"{Fore.CYAN}Press Enter to continue...{Style.RESET_ALL}")
                
                elif choice == '2':
                    print(f"{Fore.BLUE}=== Decryption Mission ==={Style.RESET_ALL}")
                    print(f"{Fore.BLUE}--- File Selection ---{Style.RESET_ALL}")
                    valid_paths = []
                    while True:
                        path = input(f"{Fore.CYAN}File to decrypt (.enc or .png, absolute path like /path/to/file, q to cancel): {Style.RESET_ALL}")
                        validated_path = self._validate_path(path)
                        if validated_path:
                            valid_paths.append(validated_path)
                        elif path.lower() == 'q':
                            break
                        add_another = input(f"{Fore.CYAN}Add another file? (y/n): {Style.RESET_ALL}").lower()
                        if add_another != 'y':
                            break
                    if not valid_paths:
                        print(f"{Fore.YELLOW}⚠️ No files selected. Back to the menu!{Style.RESET_ALL}")
                        input(f"{Fore.CYAN}Press Enter to continue...{Style.RESET_ALL}")
                        continue
                    print(f"{Fore.YELLOW}Selected files: {', '.join(valid_paths)}{Style.RESET_ALL}")
                    print(f"{Fore.BLUE}--- Password ---{Style.RESET_ALL}")
                    password = getpass(f"{Fore.CYAN}Password: {Style.RESET_ALL}")
                    os.system('clear' if os.name == 'posix' else 'cls')
                    for path in valid_paths:
                        self.decrypt_file(path, password)
                    input(f"{Fore.CYAN}Press Enter to continue...{Style.RESET_ALL}")
                
                elif choice == '3':
                    self.configure()
                    input(f"{Fore.CYAN}Press Enter to continue...{Style.RESET_ALL}")
                
                elif choice == '4':
                    print(f"{Fore.GREEN}🎉 Peace out! Keep those files safe!{Style.RESET_ALL}")
                    break
                
                elif choice == '42':
                    print(f"{Fore.YELLOW}🌌 The Answer to Life, the Universe, and Encryption!{Style.RESET_ALL}")
                    input(f"{Fore.CYAN}Press Enter to continue...{Style.RESET_ALL}")
                
                else:
                    print(f"{Fore.RED}🚫 Bad choice. Pick a number, not a riddle!{Style.RESET_ALL}")
                    input(f"{Fore.CYAN}Press Enter to continue...{Style.RESET_ALL}")

    tool = EncryptionTool()
    tool.run()