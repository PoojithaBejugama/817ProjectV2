import os
import json
import hmac
import hashlib
from base64 import b64encode, b64decode
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

# =============================
# Utilities for Encryption, MAC, Nonces, Key Management
# Used across server components
# =============================

# === Symmetric Encryption Setup ===
# Using AES in CBC mode with random IVs for confidentiality

BLOCK_SIZE = 128  # AES block size in bits
KEY_SIZE = 32     # 256-bit AES key

backend = default_backend()

def generate_nonce(size=16):
    return os.urandom(size)

def pad(data):
    padder = padding.PKCS7(BLOCK_SIZE).padder()
    return padder.update(data) + padder.finalize()

def unpad(data):
    unpadder = padding.PKCS7(BLOCK_SIZE).unpadder()
    return unpadder.update(data) + unpadder.finalize()

def encrypt(key, plaintext):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(pad(plaintext)) + encryptor.finalize()
    
    return iv + ciphertext  # IV prepended for decryption

def decrypt(key, ciphertext):
    iv = ciphertext[:16]
    ct = ciphertext[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ct) + decryptor.finalize()
    return unpad(padded_plaintext)

# === MAC (Message Authentication Code) ===

def generate_mac(mac_key, data):
    return hmac.new(mac_key, data, hashlib.sha256).digest()

def verify_mac(mac_key, data, received_mac):
    expected = generate_mac(mac_key, data)
    return hmac.compare_digest(expected, received_mac)

# === Key Management ===

# def load_user_key(username):
#     # Simulated user key store (pre-shared keys)
#     with open('server/user_keys.json', 'r') as f:
#         key_store = json.load(f)
#     return bytes.fromhex(key_store[username])

def load_user_key(username):
    with open('server/user_keys.json', 'r') as f:
        key_store = json.load(f)
        print(f"Loaded key store: {key_store}")  # Debugging line
    key_bytes = bytes.fromhex(key_store[username])
    if len(key_bytes) != 32:
        raise ValueError(f"Invalid key length ({len(key_bytes)} bytes) for user {username}. Must be 32.")
    return key_bytes

def get_audit_key():
    return b"AUDIT_LOG_SECRET_KEY_32_BYTES!!!" # has to be 32 characters long for AES-256