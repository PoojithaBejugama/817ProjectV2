import json
import time
from utils import encrypt, decrypt, generate_mac, verify_mac
from audit_log import log_encrypted_action
from auth_protocol import authenticate_and_generate_master_secret
from key_derivation import derive_keys
from utils import get_audit_key


# =================================================================================
# Point 4: Secure Transaction Protocol (Server Side)
# Handles encrypted & integrity-protected transactions: deposit, withdraw, balance
# =================================================================================


# Simulated in-memory account storage
db = {
    'alice': 1000,
    'bob': 500,
    'charlie': 750
}


def handle_client(conn):
    """
    Handles a connected client by processing encrypted and integrity-protected
    transactions such as deposit, withdraw, balance inquiry, and log viewing.

    Parameters:
        conn: The socket connection to the client.

    Returns:
        None
    """


    # Step 1: Authenticate the client and establish a shared master secret
    username, master_secret = authenticate_and_generate_master_secret(conn)


    # Step 2: Derive encryption and MAC keys from the master secret
    k_enc, k_mac = derive_keys(master_secret)


    while True:
        # Step 3: Receive an encrypted packet from the client
        encrypted_packet = conn.recv(4096)
        if not encrypted_packet:
            break  


        try:
            # Step 4: Extract the payload and MAC from the packet
            payload_json, mac = encrypted_packet[:-32], encrypted_packet[-32:]


            # Step 5: Verify the integrity of the payload using the MAC
            if not verify_mac(k_mac, payload_json, mac):
                raise Exception("MAC verification failed")


            # Step 6: Decrypt the payload to retrieve the client's request
            decrypted_payload = decrypt(k_enc, payload_json)
            request = json.loads(decrypted_payload.decode())
            action = request['action']  # Extract the requested action
            timestamp = time.strftime('%Y-%m-%d %H:%M:%S')  # Generate a timestamp


            # Step 7: Process the requested action
            if action == 'deposit':
                amount = request['amount']
                db[username] += amount  # Update the user's balance
                result = f"Deposited ${amount}. New balance: ${db[username]}"
                log_encrypted_action(username, action, timestamp)  # Log the action

            elif action == 'withdraw':
                amount = request['amount']
                if db[username] >= amount:
                    db[username] -= amount  # Deduct the amount from the user's balance
                    result = f"Withdrew ${amount}. New balance: ${db[username]}"
                else:
                    result = "Insufficient funds."
                log_encrypted_action(username, action, timestamp)  # Log the action

            elif action == 'balance':
                result = f"Current balance: ${db[username]}"
                log_encrypted_action(username, action, timestamp)  # Log the action




            elif action == 'view_log':
                user_log_file = f"server/audit_logs/{username}.enc"  # Path to the user's log file
                result_lines = []
                try:
                    # Open the log file and decrypt each entry
                    with open(user_log_file, 'rb') as f:
                        for line in f:
                            try:
                                decrypted = decrypt(get_audit_key(), line.strip())
                                entry = json.loads(decrypted.decode())
                                result_lines.append(f"{entry['timestamp']} - {entry['customer_id']} - {entry['action']}")
                            except Exception:
                                continue  # Skip invalid log entries
                    result = "\n".join(result_lines) if result_lines else "No logs found."
                except FileNotFoundError:
                    result = "No log file found."




            else:
                result = "Invalid action."


            # Step 8: Log the action (for audit purposes)
            log_encrypted_action(username, action, timestamp)


            # Step 9: Prepare the response to send back to the client
            response = json.dumps({"result": result}).encode()  # Serialize the result
            encrypted_response = encrypt(k_enc, response)  # Encrypt the response
            response_mac = generate_mac(k_mac, encrypted_response)  # Generate a MAC for the response
            conn.sendall(encrypted_response + response_mac)  # Send the encrypted response with the MAC


        except Exception as e:
            # Step 10: Handle errors and send an error response to the client
            error_msg = json.dumps({"result": str(e)}).encode()  # Serialize the error message
            encrypted_error = encrypt(k_enc, error_msg)  # Encrypt the error message
            error_mac = generate_mac(k_mac, encrypted_error)  # Generate a MAC for the error message
            conn.sendall(encrypted_error + error_mac)  # Send the encrypted error response with the MAC