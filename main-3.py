import os
import zipfile
import hashlib
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.padding import PKCS7
from getpass import getpass


def validate_path(paths):
    """Validate if the given paths exist."""
    for path in paths:
        if not os.path.exists(path):
            raise ValueError(f"Path '{path}' does not exist. Please provide a valid file or directory.")


def compress_to_zip(input_path, output_path):
    """Compress the given file or directory into a ZIP file."""
    try:
        with zipfile.ZipFile(output_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            if os.path.isfile(input_path):
                zipf.write(input_path, os.path.basename(input_path))
            else:
                for root, _, files in os.walk(input_path):
                    for file in files:
                        full_path = os.path.join(root, file)
                        arcname = os.path.relpath(full_path, start=input_path)
                        zipf.write(full_path, arcname)
        print(f"Data successfully compressed into {output_path}")
    except Exception as e:
        raise Exception(f"Error during compression: {e}")


def derive_key(password, salt):
    """Derive a key from the password using PBKDF2-HMAC."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=200000,  
        backend=default_backend()
    )
    return kdf.derive(password.encode())


def encrypt_file(input_file, output_file, password):
    """Encrypt a file using AES encryption."""
    try:
        salt = os.urandom(16)
        iv = os.urandom(16)
        key = derive_key(password, salt)

        with open(input_file, 'rb') as f:
            plaintext = f.read()

        padder = PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(plaintext) + padder.finalize()

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        with open(output_file, 'wb') as f:
            f.write(salt + iv + ciphertext)

        print(f"File successfully encrypted into {output_file}")
    except Exception as e:
        raise Exception(f"Error during encryption: {e}")


def decrypt_file(input_file, output_file, password):
    """Decrypt a file using AES encryption."""
    try:
        with open(input_file, 'rb') as f:
            data = f.read()

        salt = data[:16]
        iv = data[16:32]
        ciphertext = data[32:]
        key = derive_key(password, salt)

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        unpadder = PKCS7(algorithms.AES.block_size).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

        with open(output_file, 'wb') as f:
            f.write(plaintext)

        print(f"File successfully decrypted into {output_file}")
    except Exception as e:
        raise Exception(f"Error during decryption: {e}")


def extract_zip(zip_file, extract_dir):
    """Extract the ZIP file into the specified directory."""
    try:
        with zipfile.ZipFile(zip_file, 'r') as zipf:
            zipf.extractall(extract_dir)
        print(f"Successfully extracted {zip_file} to {extract_dir}")
    except Exception as e:
        raise Exception(f"Error during extraction: {e}")


def secure_delete(file_path):
    """Securely delete a file."""
    try:
        os.remove(file_path)
        print(f"Securely deleted {file_path}")
    except Exception as e:
        raise Exception(f"Error during secure deletion: {e}")


def encrypt_files(files, password):
    """Encrypt multiple files with the same password."""
    for file in files:
        try:
            zip_file = file + '.zip'
            compress_to_zip(file, zip_file)
            encrypted_file = zip_file + '.enc'
            encrypt_file(zip_file, encrypted_file, password)
            secure_delete(zip_file)  
            print(f"Encrypted {file} into {encrypted_file}")
        except Exception as e:
            print(f"Error encrypting {file}: {e}")


def decrypt_files(files, password):
    """Decrypt multiple files, try default password for all, then ask for passwords separately."""
    mismatched_files = []

    
    for file in files:
        zip_file = file + '.zip'
        output_file = zip_file.replace('.enc', '_decrypted.zip')

        try:
            decrypt_file(file, output_file, password)
            print(f"Decrypted {file} into {output_file}")
        except Exception:
            mismatched_files.append(file)

    
    if mismatched_files:
        print(f"Default password didn't work for {len(mismatched_files)} file(s). Please enter passwords for each.")
        for file in mismatched_files:
            new_password = getpass(f"Password for {file}: ")
            zip_file = file + '.zip'
            output_file = zip_file.replace('.enc', '_decrypted.zip')

            try:
                decrypt_file(file, output_file, new_password)
                print(f"Decrypted {file} into {output_file}")
            except Exception as e:
                print(f"Error decrypting {file} with the new password: {e}")

    # Now extract the ZIP files
    for file in files:
        zip_file = file + '.zip'
        output_file = zip_file.replace('.enc', '_decrypted.zip')
        if os.path.exists(output_file):
            extract_dir = output_file.replace('.zip', '')
            extract_zip(output_file, extract_dir)

            
            secure_delete(output_file)  
            secure_delete(file)        


def encryption_mode():
    """Handle the encryption operations and stay in the mode until the user chooses to return to the main menu."""
    while True:
        print("\nEncryption Mode")
        try:
            paths = input("Enter the paths of the files or directories to encrypt (separated by spaces): ").split()
            validate_path(paths)
            password = getpass("Enter a strong password for encryption: ")
            encrypt_files(paths, password)

            
            choice = input("\nDo you want to perform another encryption or go back to the main menu? (y to continue, b to go back): ").lower()
            if choice == 'b':
                break
            elif choice != 'y':
                break

        except Exception as e:
            print(f"Error: {e}")
            choice = input("Do you want to try again or go back to the main menu? (y to try again, b to go back): ").lower()
            if choice == 'b':
                break
            elif choice != 'y':
                break


def decryption_mode():
    """Handle the decryption operations and stay in the mode until the user chooses to return to the main menu."""
    while True:
        print("\nDecryption Mode")
        try:
            files = input("Enter the paths of the files to decrypt (separated by spaces): ").split()
            validate_path(files)
            password = getpass("Enter the password for decryption (default password): ")
            decrypt_files(files, password)

            # Ask if the user wants to continue in decryption mode or go back to the main menu
            choice = input("\nDo you want to perform another decryption or go back to the main menu? (y to continue, b to go back): ").lower()
            if choice == 'b':
                break
            elif choice != 'y':
                break

        except Exception as e:
            print(f"Error: {e}")
            choice = input("Do you want to try again or go back to the main menu? (y to try again, b to go back): ").lower()
            if choice == 'b':
                break
            elif choice != 'y':
                break


def main():
    """Main function to handle user input and process encryption/decryption."""
    while True:
        print("\nEncryption Tool")
        print("1. Encrypt multiple files or directories")
        print("2. Decrypt multiple files")
        print("3. Exit")

        choice = input("Select an option: ")

        if choice == '1':
            encryption_mode()

        elif choice == '2':
            decryption_mode()

        elif choice == '3':
            print("Exiting the tool. Goodbye!")
            break

        else:
            print("Invalid option. Please select again.")


if __name__ == "__main__":
    main()
