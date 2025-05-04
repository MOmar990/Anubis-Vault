import importlib
import subprocess
import sys

# *KABOOM!* Checking if we've got our superhero tools before we start!
def check_dependencies() -> None:
    dependencies = {'cryptography': 'cryptography', 'stegano': 'stegano', 'Pillow': 'PIL'}
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
        print("  pip install cryptography stegano Pillow")
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
        print("  pip install cryptography stegano Pillow")
        sys.exit(1)

# *BZZT!* Make sure we’ve got our tools before we load the big guns!
check_dependencies()

if __name__ == "__main__":
    import os
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
                        data.pop('_comments', None)  # Shh, comments, you're not invited!
                        self.config.update(data)
            except Exception as e:
                print(f"Config file threw a tantrum: {e}")

        # *SPLAT!* Spitting out the config to disk for next time.
        def save_config(self) -> bool:
            try:
                with open(self.config_file, 'w') as f:
                    json.dump(self.config, f, indent=4)
                return True
            except Exception as e:
                print(f"Couldn't save config: {e}")
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
                print(f"Compression flopped: {e}")
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
                print("File type? Beats me, going with .bin!")
                return '.bin'

        # *POP!* Unzipping your file back to its original glory!
        def decompress(self, zip_path: str, output_path: str) -> Tuple[bool, str]:
            try:
                temp_extract = Path(self.config.get('temp_dir')) / 'extracted'
                os.makedirs(temp_extract, exist_ok=True)
                
                with zipfile.ZipFile(zip_path, 'r') as zipf:
                    zipf.extractall(temp_extract)
                
                gz_files = list(temp_extract.glob('*.gz'))
                if not gz_files:
                    print("No .gz file in the ZIP. What’s going on?")
                    return False, ''
                
                temp_output = temp_extract / 'temp_decompressed'
                with gzip.open(gz_files[0], 'rb') as gz_file, open(temp_output, 'wb') as out_file:
                    shutil.copyfileobj(gz_file, out_file)
                
                extension = self._detect_file_type(temp_output)
                
                shutil.move(temp_output, output_path)
                
                if not os.path.exists(output_path):
                    print(f"Output file vanished: {output_path}")
                    return False, ''
                
                return True, extension
            except Exception as e:
                print(f"Decompression went poof: {e}")
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
                print(f"Encryption fizzled: {e}")
                return None

        # *BOOM!* Busting your file out of its .enc prison!
        def decrypt(self, input_path: str, password: str, output_dir: Path) -> Optional[str]:
            try:
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
                                print(f"Wrong key or busted file: {e}")
                                return None
                    
                    calculated_hash = self._calculate_hash(output_path)
                    if calculated_hash != stored_hash:
                        output_path.unlink(missing_ok=True)
                        print(f"File’s been tampered with! Expected {stored_hash}, got {calculated_hash}")
                        return None
                    
                    return str(output_path)
            except Exception as e:
                print(f"Decryption crashed: {e}")
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
                        print(f"Bad image format {input_ext}. Try {', '.join(self.SUPPORTED_FORMATS)}!")
                        return None
                    
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
                    print(f"Hiding {data_path} ({data_size} bytes, hash: {data_hash})")
                    
                    carrier_size = os.path.getsize(temp_carrier)
                    max_stego_size = carrier_size * 1.2
                    with Image.open(temp_carrier) as img:
                        width, height = img.size
                        max_capacity = width * height // 8
                        if encoded_size > max_capacity:
                            required_dims = self._estimate_required_dimensions(encoded_size)
                            print(f"Image too tiny! Need {encoded_size} bytes, got {max_capacity}")
                            print(f"Grab a bigger image, like {required_dims} pixels!")
                            retry = input("New image? (y/n): ").lower()
                            if retry == 'y':
                                carrier_image = input("Gimme a new image path (e.g., /path/to/image.png): ")
                                continue
                            else:
                                print(f"No stego, but your file’s safe at: {data_path}")
                                return None
                        if encoded_size + carrier_size > max_stego_size:
                            print("Stego image would be HUGE. Try a smaller file!")
                            return None
                    
                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                    output_dir = Path(self.config.get('stego_dir')) / timestamp
                    os.makedirs(output_dir, exist_ok=True)
                    output_path = output_dir / f"{Path(carrier_image).stem}.png"
                    
                    stego_img = lsb.hide(str(temp_carrier), encoded_data)
                    stego_img.save(output_path, 'PNG', compress_level=9, optimize=True)
                    
                    print(f"Stego image ready: {output_path} ({os.path.getsize(output_path)} bytes)")
                    return str(output_path)
                except Exception as e:
                    print(f"Stego mission failed: {e}")
                    return None
                finally:
                    temp_carrier.unlink(missing_ok=True)

        # *WHOOSH!* Yanking your file out of its PNG hideout!
        def extract(self, image_path: str, output_path: str) -> bool:
            try:
                ext = Path(image_path).suffix.lower()
                if ext not in {'.png'}:
                    print("Only PNGs for stego extraction, sorry!")
                    return False
                
                encoded_data = lsb.reveal(image_path)
                if encoded_data is None:
                    print("No secret data in this image. You sure it’s stego’d?")
                    return False
                
                if isinstance(encoded_data, bytes):
                    encoded_data = encoded_data.decode('utf-8')
                elif not isinstance(encoded_data, str):
                    print("Weird data in the image. Not our stuff!")
                    return False
                
                try:
                    data = base64.b64decode(encoded_data)
                except Exception as e:
                    print(f"Base64 decode went kablooey: {e}")
                    return False
                
                data_size = len(data)
                data_hash = self._calculate_hash(data)
                with open(output_path, 'wb') as f:
                    f.write(data)
                print(f"Pulled {data_size} bytes to {output_path} (hash: {data_hash})")
                return True
            except Exception as e:
                print(f"Stego extraction flunked: {e}")
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
            if not path:
                print("Gimme a real path, not air!")
                return None
            path = path.strip()
            path = os.path.expanduser(path)
            if not (path.startswith('/') or path.startswith(os.path.expanduser('~'))):
                print(f"Relative path? Nah, go absolute like /path/to/file!")
            if not os.path.exists(path):
                print(f"Path’s a ghost: {path}")
                return None
            if is_input and not os.path.isfile(path):
                print(f"Need a file, not a folder: {path}")
                return None
            if is_input and not os.access(path, os.R_OK):
                print(f"Can’t read this file: {path}")
                return None
            if is_carrier and Path(path).suffix.lower() not in self.stego.SUPPORTED_FORMATS:
                print(f"Wrong image type {Path(path).suffix}. Use {', '.join(self.stego.SUPPORTED_FORMATS)}!")
                return None
            return path

        # *KAPOW!* Encrypting your file and maybe hiding it in a PNG!
        def encrypt_file(self, input_path: str, password: str) -> bool:
            temp_zip = None
            try:
                input_path = self._validate_path(input_path)
                if not input_path:
                    return False
                
                temp_zip = Path(self.config.get('temp_dir')) / f"{Path(input_path).name}.zip"
                if not self.compressor.compress(input_path, str(temp_zip)):
                    return False
                print(f"Squashed: {input_path} -> {temp_zip} ({os.path.getsize(temp_zip)} bytes)")
                
                output_dir = self._create_output_dir('encrypted')
                enc_path = self.encryptor.encrypt(str(temp_zip), password, output_dir)
                if not enc_path:
                    return False
                print(f"Locked tight: {input_path} -> {enc_path}")
                
                hide = input("Wanna hide it in an image? (y/n): ").lower()
                if hide == 'y':
                    carrier_image = input("Pick an image (e.g., /path/to/image.png): ")
                    stego_path = self.stego.hide(enc_path, carrier_image, self._validate_path)
                    if stego_path:
                        print(f"Hidden like a ninja: {stego_path}")
                    else:
                        print(f"No stego, but it’s safe at: {enc_path}")
                
                return True
            except Exception as e:
                print(f"Encryption went splat: {e}")
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
                    temp_enc = Path(self.config.get('temp_dir')) / 'extracted.enc'
                    if not self.stego.extract(input_path, str(temp_enc)):
                        return False
                    actual_input = str(temp_enc)
                
                output_dir = self._create_output_dir('decrypted')
                zip_path = self.encryptor.decrypt(actual_input, password, output_dir)
                if not zip_path:
                    return False
                print(f"Cracked open: {actual_input} -> {zip_path} ({os.path.getsize(zip_path)} bytes)")
                
                if is_stego:
                    original_name = input("What’s the original file name (no extension, e.g., example_file)? ")
                    if not original_name:
                        print("Need a name for this stego file!")
                        return False
                    original_name = self.encryptor._sanitize_filename(original_name)
                    original_name = Path(original_name).stem
                else:
                    original_name = Path(Path(input_path).stem).stem
                
                temp_output = output_dir / f"{original_name}_temp"
                success, extension = self.compressor.decompress(zip_path, str(temp_output))
                if not success:
                    return False
                
                final_output = output_dir / f"{original_name}{extension}"
                if temp_output.exists():
                    shutil.move(temp_output, final_output)
                
                if not final_output.exists():
                    print(f"Output file pulled a Houdini: {final_output}")
                    return False
                print(f"Freed: {input_path} -> {final_output} ({os.path.getsize(final_output)} bytes)")
                return True
            except Exception as e:
                print(f"Decryption tanked: {e}")
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
            print("\nHere’s the control panel:")
            for key, value in self.config.config.items():
                print(f"{key}: {value}")
            
            print("\nChange stuff (hit Enter to keep it chill):")
            try:
                iterations = input(f"PBKDF2 loops [{self.config.get('iterations')}]: ")
                if iterations.isdigit():
                    self.config.set('iterations', int(iterations))
                
                salt_length = input(f"Salt size [{self.config.get('salt_length')}]: ")
                if salt_length.isdigit():
                    self.config.set('salt_length', int(salt_length))
                
                output_dir = input(f"Output folder [{self.config.get('output_dir')}]: ")
                if output_dir:
                    self.config.set('output_dir', output_dir)
                
                stego_dir = input(f"Stego hideout [{self.config.get('stego_dir')}]: ")
                if stego_dir:
                    self.config.set('stego_dir', stego_dir)
                
                comp_level = input(f"Zip crunch (1-9) [{self.config.get('compression_level')}]: ")
                if comp_level.isdigit() and 1 <= int(comp_level) <= 9:
                    self.config.set('compression_level', int(comp_level))
                
                if self.config.save_config():
                    print("Config saved! You’re a genius!")
                else:
                    print("Config save failed. Blame the gremlins!")
            except Exception as e:
                print(f"Config tweak went haywire: {e}")

        # *BZZT!* The main show, where you pick your encryption adventure!
        def run(self) -> None:
            while True:
                print("\nAdvanced Encryption Tool")
                print("1. Encrypt file")
                print("2. Decrypt file")
                print("3. Configure settings")
                print("4. Exit")
                
                choice = input("\nPick your poison: ")
                
                if choice == '1':
                    valid_paths = []
                    while True:
                        path = input("File to encrypt (e.g., /path/to/file.pdf): ")
                        validated_path = self._validate_path(path)
                        if validated_path:
                            valid_paths.append(validated_path)
                        add_another = input("More files? (y/n): ").lower()
                        if add_another != 'y':
                            break
                    if not valid_paths:
                        print("No files? I’m not that bored!")
                        continue
                    password = getpass("Password: ")
                    confirm = getpass("Confirm password: ")
                    if password != confirm:
                        print("Passwords don’t match. Try again, champ!")
                        continue
                    for path in valid_paths:
                        self.encrypt_file(path, password)
                
                elif choice == '2':
                    valid_paths = []
                    while True:
                        path = input("File to decrypt (e.g., /path/to/file.enc or /path/to/file.png): ")
                        validated_path = self._validate_path(path)
                        if validated_path:
                            valid_paths.append(validated_path)
                        add_another = input("More files? (y/n): ").lower()
                        if add_another != 'y':
                            break
                    if not valid_paths:
                        print("No files to crack? Lame!")
                        continue
                    password = getpass("Password: ")
                    for path in valid_paths:
                        self.decrypt_file(path, password)
                
                elif choice == '3':
                    self.configure()
                
                elif choice == '4':
                    print("Peace out! Keep those files safe!")
                    break
                
                else:
                    print("Bad choice. Try a number, not a riddle!")

    tool = EncryptionTool()
    tool.run()