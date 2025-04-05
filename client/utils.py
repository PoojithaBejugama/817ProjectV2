import os
import json
import hmac
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

# =============================
# Client-side Cryptographic Utilities
# =============================

BLOCK_SIZE = 128
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
    return iv + ciphertext

def decrypt(key, ciphertext):
    iv = ciphertext[:16]
    ct = ciphertext[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ct) + decryptor.finalize()
    return unpad(padded_plaintext)

def generate_mac(mac_key, data):
    return hmac.new(mac_key, data, hashlib.sha256).digest()

def verify_mac(mac_key, data, received_mac):
    expected = generate_mac(mac_key, data)
    return hmac.compare_digest(expected, received_mac)

def load_user_key(username):
    with open('server/user_keys.json', 'r') as f:
        key_store = json.load(f)
    return bytes.fromhex(key_store[username])
