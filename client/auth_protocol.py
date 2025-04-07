import os
import json
import hmac
import hashlib
from utils import encrypt, decrypt, generate_nonce, load_user_key


# ===============================================================
# Point 2: Authenticated Key Distribution Protocol (Client Side)
# Mirrors server-side protocol to establish Master Secret
# ===============================================================


def start_key_exchange(sock, username):
    # Step 1: Generate a client nonce (nonce_c) for this session
    nonce_c = generate_nonce()


    # Step 2: Send ClientHello message containing the username and nonce_c
    # ClientHello = {username, nonce_c}
    client_hello = { #################include password here too
        # 'password': password,  # Include password in the ClientHello message
        'username': username,
        'nonce': nonce_c.hex()  # Convert nonce_c to a hexadecimal string for transmission
    }
    sock.sendall(json.dumps(client_hello).encode())  # Send the JSON-encoded message over the socket


    # Step 3: Receive ServerHello message from the server
    # ServerHello = ENC_K_ATM({nonce_c, nonce_s})
    K_ATM = load_user_key(username)  
    enc_response = sock.recv(4096)  
    response_json = decrypt(K_ATM, enc_response)  
    data = json.loads(response_json.decode())  # Parse the decrypted JSON data

    # Extract the server's response: nonce_c (echoed back) and nonce_s (server-generated nonce)
    received_nonce_c = bytes.fromhex(data['nonce_c'])  # Convert the received nonce_c back to bytes
    nonce_s = bytes.fromhex(data['nonce_s'])  # Convert the received nonce_s back to bytes


    # Step 4: Verify that the server echoed back the correct nonce_c
    # This ensures the server knows the shared key (K_ATM) and proves its identity
    if received_nonce_c != nonce_c:
        raise Exception("Server failed to prove identity")  


    # Step 5: Send confirmation message back to the server
    # Confirmation = ENC_K_ATM({nonce_s})
    confirmation = json.dumps({
        'nonce_s': nonce_s.hex()  # Convert nonce_s to a hexadecimal string for transmission
    }).encode()
    sock.sendall(encrypt(K_ATM, confirmation))  # Encrypt the confirmation and send it to the server


    # Step 6: Derive the Master Secret (MS) using HMAC
    # MS = HMAC(K_ATM, nonce_c || nonce_s)
    ms_input = nonce_c + nonce_s  
    master_secret = hmac.new(K_ATM, ms_input, hashlib.sha256).digest()  


    # Return the derived Master Secret (MS) to the caller
    return master_secret