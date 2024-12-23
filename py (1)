import os
import logging
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

# Utility for logging
def log_action(username, action):
    logging.basicConfig(filename="access.log", level=logging.INFO)
    logging.info(f"{username} - {action}")

# Hashing passwords (using PBKDF2 with SHA256)
def hash_password(password, salt=None):
    if salt is None:
        salt = os.urandom(16)  # Generate a random salt if none provided
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode('utf-8')), salt

# Verifying password
def verify_password(stored_hash, password, salt):
    try:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        kdf.verify(password.encode('utf-8'), stored_hash)
        return True
    except Exception as e:
        return False

# File encryption
def encrypt_file(input_file, output_file, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    with open(input_file, 'rb') as f_in:
        data = f_in.read()

    # Padding the data to be a multiple of block size
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()

    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    with open(output_file, 'wb') as f_out:
        f_out.write(encrypted_data)

# File decryption
def decrypt_file(input_file, output_file, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    with open(input_file, 'rb') as f_in:
        encrypted_data = f_in.read()

    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

    # Unpadding the decrypted data
    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(decrypted_data) + unpadder.finalize()

    with open(output_file, 'wb') as f_out:
        f_out.write(data)

# File hash (SHA256)
def hash_file(file_name):
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    with open(file_name, 'rb') as f:
        while chunk := f.read(8192):
            digest.update(chunk)
    return digest.finalize().hex()

# Secure file deletion (shredding)
def secure_delete(file_path, passes=3):
    """Shreds a file by overwriting it with random data multiple times before deleting."""
    try:
        with open(file_path, 'r+b') as f:
            length = os.path.getsize(file_path)
            for _ in range(passes):
                # Overwrite the file with random data
                f.seek(0)
                f.write(os.urandom(length))
                f.flush()
                os.fsync(f.fileno())
        
        # After overwriting, remove the file
        os.remove(file_path)
        print(f"File {file_path} has been securely deleted.")
        log_action("user123", f"Securely deleted file: {file_path}")
    except Exception as e:
        print(f"Error deleting file: {e}")
        log_action("user123", f"Failed to securely delete file: {file_path}")

def main():
    # Simulated user credentials
    username = "user123"
    password = "securepassword"
    stored_hash, salt = hash_password(password)  # Store the salt along with the hash

    # Authentication
    input_username = input("Enter username: ")
    input_password = input("Enter password: ")

    if input_username != username or not verify_password(stored_hash, input_password, salt):
        print("Authentication failed!")
        log_action(input_username, "Failed authentication")
        return
    log_action(input_username, "Authenticated successfully")

    # Cryptographic setup
    key = os.urandom(32)  # AES key length 256 bits
    iv = os.urandom(16)  # AES block size (128 bits)

    # Main menu
    while True:
        print("\nFile Protection System")
        print("1. Encrypt a file")
        print("2. Decrypt a file")
        print("3. Verify file integrity")
        print("4. Securely delete a file")
        print("5. Exit")
        choice = int(input("Enter your choice: "))

        if choice == 1:
            input_file = input("Enter input file name: ")
            output_file = input("Enter output (encrypted) file name: ")

            encrypt_file(input_file, output_file, key, iv)
            log_action(username, f"Encrypted file: {input_file}")
            print("File encrypted successfully.")

        elif choice == 2:
            input_file = input("Enter encrypted file name: ")
            output_file = input("Enter output (decrypted) file name: ")

            decrypt_file(input_file, output_file, key, iv)
            log_action(username, f"Decrypted file: {input_file}")
            print("File decrypted successfully.")

        elif choice == 3:
            input_file = input("Enter file name for integrity check: ")
            file_hash = hash_file(input_file)
            print(f"File hash: {file_hash}")
            log_action(username, f"Verified integrity of file: {input_file}")

        elif choice == 4:
            file_to_delete = input("Enter file name to securely delete: ")
            secure_delete(file_to_delete)  # Securely delete the file
            print("File securely deleted.")

        elif choice == 5:
            print("Exiting...")
            log_action(username, "Exited the system")
            break

        else:
            print("Invalid choice. Please try again.")


if __name__ == "__main__":
    main()
