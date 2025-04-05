import os
import json
import hmac
import hashlib
from utils import encrypt, decrypt, generate_nonce, load_user_key

# =============================
# Point 2: Authenticated Key Distribution Protocol (Client Side)
# Mirrors server-side protocol to establish Master Secret
# =============================

def start_key_exchange(sock, username):
    nonce_c = generate_nonce()

    # Step 1: Send ClientHello {username, nonce_c}
    client_hello = {
        'username': username,
        'nonce': nonce_c.hex()
    }
    sock.sendall(json.dumps(client_hello).encode())

    # Step 2: Receive ServerHello = ENC_K_ATM({nonce_c, nonce_s})
    K_ATM = load_user_key(username)
    enc_response = sock.recv(4096)
    response_json = decrypt(K_ATM, enc_response)
    data = json.loads(response_json.decode())
    received_nonce_c = bytes.fromhex(data['nonce_c'])
    nonce_s = bytes.fromhex(data['nonce_s'])

    if received_nonce_c != nonce_c:
        raise Exception("Server failed to prove identity")

    # Step 3: Send back ENC_K_ATM({nonce_s})
    confirmation = json.dumps({
        'nonce_s': nonce_s.hex()
    }).encode()
    sock.sendall(encrypt(K_ATM, confirmation))

    # Create Master Secret: MS = HMAC(K_ATM, nonce_c || nonce_s)
    ms_input = nonce_c + nonce_s
    master_secret = hmac.new(K_ATM, ms_input, hashlib.sha256).digest()

    return master_secret
