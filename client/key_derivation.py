import hmac
import hashlib


# =============================
# Point 3: Key Derivation (Client Side)
# Same as server logic to derive symmetric keys
# =============================


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

    # Derive the encryption key (k_enc) using HMAC with the master secret
    # and the string "encryption" as the message.
    k_enc = hmac.new(master_secret, b"encryption", hashlib.sha256).digest()


    # Derive the MAC key (k_mac) using HMAC with the master secret
    # and the string "mac" as the message.
    k_mac = hmac.new(master_secret, b"mac", hashlib.sha256).digest()


    # Return the derived keys as a tuple
    return k_enc, k_mac
