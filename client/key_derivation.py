import hmac
import hashlib

# =============================
# Point 3: Key Derivation (Client Side)
# Same as server logic to derive symmetric keys
# =============================

def derive_keys(master_secret):
    k_enc = hmac.new(master_secret, b"encryption", hashlib.sha256).digest()
    k_mac = hmac.new(master_secret, b"mac", hashlib.sha256).digest()
    return k_enc, k_mac
