import hmac
import hashlib


# ==========================================================
# Point 3: Key Derivation
# Derives encryption key and MAC key from the Master Secret
# ==========================================================


def derive_keys(master_secret):
    """
    Derives symmetric keys for encryption and message authentication
    using the provided Master Secret (MS).

    Parameters:
        master_secret (bytes): The shared Master Secret (MS) established
                               during the key exchange process.

    Returns:
        tuple: A tuple containing two keys:
               - k_enc (bytes): Key for encryption
               - k_mac (bytes): Key for message authentication (MAC)
    """


    # Step 1: Derive the encryption key (k_enc)
    # Use HMAC with the master secret as the key and the string "encryption"
    # as the message to derive a unique encryption key.
    k_enc = hmac.new(master_secret, b"encryption", hashlib.sha256).digest()


    # Step 2: Derive the MAC key (k_mac)
    # Use HMAC with the master secret as the key and the string "mac"
    # as the message to derive a unique key for message authentication.
    k_mac = hmac.new(master_secret, b"mac", hashlib.sha256).digest()


    # Step 3: Return the derived keys as a tuple
    return k_enc, k_mac
