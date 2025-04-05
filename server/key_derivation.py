import hmac
import hashlib

# =============================
# Point 3: Key Derivation
# Derives encryption key and MAC key from the Master Secret
# =============================

def derive_keys(master_secret):
    # Encryption Key: HMAC(master_secret, b"encryption")
    k_enc = hmac.new(master_secret, b"encryption", hashlib.sha256).digest()

    # MAC Key: HMAC(master_secret, b"mac")
    k_mac = hmac.new(master_secret, b"mac", hashlib.sha256).digest()

    return k_enc, k_mac
