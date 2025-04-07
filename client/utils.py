import os
import json
import hmac
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend


# ====================================
# Client-side Cryptographic Utilities
# ====================================


BLOCK_SIZE = 128  # Block size for AES encryption (in bits)
backend = default_backend()  # Backend for cryptographic operations


def generate_nonce(size=16):
    """
    Generates a random nonce (number used once) of the specified size.

    Parameters:
        size (int): The size of the nonce in bytes (default is 16).

    Returns:
        bytes: A randomly generated nonce.
    """
    return os.urandom(size)


def pad(data):
    """
    Pads the input data to make it a multiple of the block size using PKCS7 padding.

    Parameters:
        data (bytes): The plaintext data to be padded.

    Returns:
        bytes: The padded data.
    """
    padder = padding.PKCS7(BLOCK_SIZE).padder()
    return padder.update(data) + padder.finalize()


def unpad(data):
    """
    Removes PKCS7 padding from the input data.

    Parameters:
        data (bytes): The padded data to be unpadded.

    Returns:
        bytes: The original unpadded data.
    """
    unpadder = padding.PKCS7(BLOCK_SIZE).unpadder()
    return unpadder.update(data) + unpadder.finalize()


def encrypt(key, plaintext):
    """
    Encrypts the plaintext using AES in CBC mode with a random IV.

    Parameters:
        key (bytes): The encryption key.
        plaintext (bytes): The plaintext data to be encrypted.

    Returns:
        bytes: The IV concatenated with the ciphertext.
    """
    iv = os.urandom(16)  # Generate a random initialization vector (IV)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(pad(plaintext)) + encryptor.finalize()
    return iv + ciphertext  # Return IV + ciphertext for decryption


def decrypt(key, ciphertext):
    """
    Decrypts the ciphertext using AES in CBC mode.

    Parameters:
        key (bytes): The decryption key.
        ciphertext (bytes): The IV concatenated with the ciphertext.

    Returns:
        bytes: The decrypted plaintext.
    """
    iv = ciphertext[:16]  # Extract the IV (first 16 bytes)
    ct = ciphertext[16:]  # Extract the actual ciphertext
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ct) + decryptor.finalize()
    return unpad(padded_plaintext)  # Remove padding to get the original plaintext


def generate_mac(mac_key, data):
    """
    Generates a Message Authentication Code (MAC) for the given data.

    Parameters:
        mac_key (bytes): The key used for HMAC.
        data (bytes): The data to authenticate.

    Returns:
        bytes: The generated MAC.
    """
    return hmac.new(mac_key, data, hashlib.sha256).digest()


def verify_mac(mac_key, data, received_mac):
    """
    Verifies the integrity of the data using the provided MAC.

    Parameters:
        mac_key (bytes): The key used for HMAC.
        data (bytes): The data to verify.
        received_mac (bytes): The MAC received for verification.

    Returns:
        bool: True if the MAC is valid, False otherwise.
    """
    expected = generate_mac(mac_key, data)  # Generate the expected MAC
    return hmac.compare_digest(expected, received_mac)  # Compare securely to prevent timing attacks


def load_user_key(username):
    """
    Loads the user's pre-shared key from a JSON file.

    Parameters:
        username (str): The username whose key is to be loaded.

    Returns:
        bytes: The user's key as a byte array.
    """
    with open('server/user_keys.json', 'r') as f:
        key_store = json.load(f)  # Load the key store from the JSON file
        print(f"\n[client]Loaded key for {username}: {key_store[username]}")
    return bytes.fromhex(key_store[username])  # Convert the key from hex to bytes
