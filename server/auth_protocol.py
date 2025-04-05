import os
import json
import hmac
import hashlib
from utils import encrypt, decrypt, generate_nonce, load_user_key

# =============================
# Point 2: Authenticated Key Distribution Protocol (Server Side)
# Securely establishes a Master Secret between ATM and Server
# =============================

def authenticate_and_generate_master_secret(conn):
    # Step 1: Receive ClientHello {username, nonce_c}
    raw = conn.recv(4096)
    client_hello = json.loads(raw.decode())
    username = client_hello['username']
    nonce_c = bytes.fromhex(client_hello['nonce'])

    # Load pre-shared key for this user
    K_ATM = load_user_key(username)

    # Step 2: ServerHello = ENC_K_ATM({nonce_c, nonce_s})
    nonce_s = generate_nonce()
    server_hello_data = json.dumps({
        'nonce_c': nonce_c.hex(),
        'nonce_s': nonce_s.hex()
    }).encode()
    encrypted_response = encrypt(K_ATM, server_hello_data)
    conn.sendall(encrypted_response)

    # Step 3: ClientResponse = ENC_K_ATM({nonce_s})
    raw = conn.recv(4096)
    decrypted_response = decrypt(K_ATM, raw)
    response_data = json.loads(decrypted_response.decode())
    received_nonce_s = bytes.fromhex(response_data['nonce_s'])

    if received_nonce_s != nonce_s:
        raise Exception("Authentication failed: Nonce mismatch")

    # Generate Master Secret: MS = HMAC(K_ATM, nonce_c || nonce_s)
    ms_input = nonce_c + nonce_s
    master_secret = hmac.new(K_ATM, ms_input, hashlib.sha256).digest()

    return username, master_secret
