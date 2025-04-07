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
    """
    Authenticates the client and securely establishes a shared Master Secret (MS)
    between the client and the server using a nonce-based challenge-response protocol.

    Parameters:
        conn: The socket connection to the client.

    Returns:
        tuple: A tuple containing:
               - username (str): The authenticated username.
               - master_secret (bytes): The derived Master Secret (MS).
    """

    
    # Step 1: Receive ClientHello {username, nonce_c}
    # The client sends their username and a randomly generated nonce (nonce_c).
    raw = conn.recv(4096)  
    client_hello = json.loads(raw.decode())  
    username = client_hello['username']   ##########################check passsord first here
    nonce_c = bytes.fromhex(client_hello['nonce'])
    #password = client_hello['password']  # Extract the password from the ClientHello message
    # Check if the password is correct for the given username
    # This is a placeholder for the actual password verification logic.
    # In a real implementation, you would check the password against a secure database or hash.

    # Load pre-shared key for this user
    # The server retrieves the pre-shared key (K_ATM) associated with the username.
    K_ATM = load_user_key(username)


    # Step 2: ServerHello = ENC_K_ATM({nonce_c, nonce_s})
    # The server generates its own nonce (nonce_s) and sends both nonces back to the client,
    # encrypted with the pre-shared key (K_ATM).
    nonce_s = generate_nonce()  # Generate a random server nonce
    server_hello_data = json.dumps({
        'nonce_c': nonce_c.hex(),  # Include the client's nonce (nonce_c) in hex format
        'nonce_s': nonce_s.hex()   # Include the server's nonce (nonce_s) in hex format
    }).encode()
    encrypted_response = encrypt(K_ATM, server_hello_data)  # Encrypt the response using K_ATM
    conn.sendall(encrypted_response)  # Send the encrypted ServerHello message to the client


    # Step 3: ClientResponse = ENC_K_ATM({nonce_s})
    # The client responds by encrypting the server's nonce (nonce_s) with the pre-shared key (K_ATM).
    raw = conn.recv(4096)  
    decrypted_response = decrypt(K_ATM, raw)  
    response_data = json.loads(decrypted_response.decode())  
    received_nonce_s = bytes.fromhex(response_data['nonce_s'])  

    # Verify the received nonce_s matches the one sent by the server
    # This ensures the client knows the pre-shared key (K_ATM) and proves its identity.
    if received_nonce_s != nonce_s:
        raise Exception("Authentication failed: Nonce mismatch")  # Raise an error if the nonces don't match


    # Step 4: Generate Master Secret: MS = HMAC(K_ATM, nonce_c || nonce_s)
    # The server derives the Master Secret (MS) by concatenating nonce_c and nonce_s
    # and applying HMAC with the pre-shared key (K_ATM).
    ms_input = nonce_c + nonce_s  # Concatenate the client and server nonces
    master_secret = hmac.new(K_ATM, ms_input, hashlib.sha256).digest()  # Derive the Master Secret (MS)


    # Return the authenticated username and the derived Master Secret
    return username, master_secret