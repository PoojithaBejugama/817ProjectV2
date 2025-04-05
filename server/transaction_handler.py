import json
import time
from utils import encrypt, decrypt, generate_mac, verify_mac
from audit_log import log_encrypted_action
from auth_protocol import authenticate_and_generate_master_secret
from key_derivation import derive_keys

# =============================
# Point 4: Secure Transaction Protocol (Server Side)
# Handles encrypted & integrity-protected transactions: deposit, withdraw, balance
# =============================

# Simulated in-memory account storage
db = {
    'alice': 1000,
    'bob': 500,
    'charlie': 750
}

def handle_client(conn):
    username, master_secret = authenticate_and_generate_master_secret(conn)
    k_enc, k_mac = derive_keys(master_secret)

    while True:
        encrypted_packet = conn.recv(4096)
        if not encrypted_packet:
            break

        try:
            # Expecting packet: ENC({payload}) || MAC
            payload_json, mac = encrypted_packet[:-32], encrypted_packet[-32:]

            if not verify_mac(k_mac, payload_json, mac):
                raise Exception("MAC verification failed")

            decrypted_payload = decrypt(k_enc, payload_json)
            request = json.loads(decrypted_payload.decode())
            action = request['action']
            timestamp = time.strftime('%Y-%m-%d %H:%M:%S')

            # Process action
            if action == 'deposit':
                amount = request['amount']
                db[username] += amount
                result = f"Deposited ${amount}. New balance: ${db[username]}"

            elif action == 'withdraw':
                amount = request['amount']
                if db[username] >= amount:
                    db[username] -= amount
                    result = f"Withdrew ${amount}. New balance: ${db[username]}"
                else:
                    result = "Insufficient funds."

            elif action == 'balance':
                result = f"Current balance: ${db[username]}"

            else:
                result = "Invalid action."

            # Audit log encryption (Point 4: encrypted logs)
            log_encrypted_action(username, action, timestamp)

            # Prepare response
            response = json.dumps({"result": result}).encode()
            encrypted_response = encrypt(k_enc, response)
            response_mac = generate_mac(k_mac, encrypted_response)
            conn.sendall(encrypted_response + response_mac)

        except Exception as e:
            error_msg = json.dumps({"result": str(e)}).encode()
            encrypted_error = encrypt(k_enc, error_msg)
            error_mac = generate_mac(k_mac, encrypted_error)
            conn.sendall(encrypted_error + error_mac)