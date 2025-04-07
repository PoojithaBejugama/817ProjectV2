import socket
import threading
from transaction_handler import handle_client
import os
import json
import time
from utils import encrypt, decrypt, generate_mac, verify_mac
from audit_log import log_encrypted_action
from auth_protocol import authenticate_and_generate_master_secret
from key_derivation import derive_keys
from utils import get_audit_key


# =============================
# Point 1: Multithreaded Bank Server
# This server listens for incoming ATM client connections,
# and for each client, it spawns a new thread to handle their session securely.
# =============================


HOST = '127.0.0.1'  
PORT = 65432        


# Simulated in-memory account storage
db = {
    'alice': 1000,
    'bob': 500,
    'charlie': 750
}


def client_thread(conn, addr): #when the server accepts a connection, it creates a new thread to handle the client
    print(f"\nConnected by {addr}")
    try:
        handle_client(conn)
    except Exception as e:
        print(f"\nError handling client {addr}: {e}")
    finally:
        conn.close()
        print(f"\nDisconnected {addr}")


def handle_client(conn): #this is where the server handles all incoming requests from the client
    ##############passeorsd handler code need to added here
    """
    Handles a connected client by processing encrypted and integrity-protected
    transactions such as deposit, withdraw, balance inquiry, and log viewing.

    Parameters:
        conn: The socket connection to the client.

    Returns:
        None
    """


    # Step 1: Authenticate the client and establish a shared master secret
    # This ensures the client is legitimate and establishes a secure session.
    username, master_secret = authenticate_and_generate_master_secret(conn) #############will also recieve password here

    # Step 2: Derive encryption and MAC keys from the master secret
    # These keys are used for secure communication with the client.
    k_enc, k_mac = derive_keys(master_secret)


    while True:
        # Step 3: Receive an encrypted packet from the client
        # The packet contains the client's request and a MAC for integrity verification.
        encrypted_packet = conn.recv(4096)
        if not encrypted_packet:
            break  # Exit the loop if the connection is closed


        try:
            # Step 4: Extract the payload and MAC from the packet
            # The last 32 bytes of the packet are the MAC, and the rest is the payload.
            payload_json, mac = encrypted_packet[:-32], encrypted_packet[-32:]


            # Step 5: Verify the integrity of the payload using the MAC
            # If the MAC does not match, the data may have been tampered with.
            if not verify_mac(k_mac, payload_json, mac):
                raise Exception("MAC verification failed")


            # Step 6: Decrypt the payload to retrieve the client's request
            # The payload is decrypted using the encryption key (k_enc).
            decrypted_payload = decrypt(k_enc, payload_json)
            request = json.loads(decrypted_payload.decode())  
            action = request['action']  
            timestamp = time.strftime('%Y-%m-%d %H:%M:%S')  


            # Step 7: Process the requested action
            if action == 'deposit':
                amount = request['amount']
                db[username] += amount  # Update the user's balance
                result = f"Deposited ${amount}. New balance: ${db[username]}"
                log_encrypted_action(username, action, timestamp)  # Log the action securely

            elif action == 'withdraw':
                amount = request['amount']
                if db[username] >= amount:
                    db[username] -= amount  # Deduct the amount from the user's balance
                    result = f"Withdrew ${amount}. New balance: ${db[username]}"
                else:
                    result = "Insufficient funds."
                log_encrypted_action(username, action, timestamp)  # Log the action securely

            elif action == 'balance':
                result = f"Current balance: ${db[username]}"
                log_encrypted_action(username, action, timestamp)  # Log the action securely

            elif action == 'view_log':
                user_log_file = f"server/audit_logs/{username}.enc"  # Path to the user's log file
                result_lines = []
                try:
                    # Open the log file and decrypt each entry
                    with open(user_log_file, 'rb') as f:
                        for line in f:
                            try:
                                decrypted = decrypt(get_audit_key(), line.strip())  # Decrypt the log entry
                                entry = json.loads(decrypted.decode())  # Parse the JSON log entry
                                result_lines.append(f"{entry['timestamp']} - {entry['customer_id']} - {entry['action']}")
                            except Exception:
                                continue  # Skip invalid log entries
                    result = "\n".join(result_lines) if result_lines else "No logs found."
                except FileNotFoundError:
                    result = "No log file found."


            else:
                # Handle invalid actions
                result = "Invalid action."


            # Step 8: Log the action (for audit purposes)
            # This ensures all actions are recorded securely.
            log_encrypted_action(username, action, timestamp)


            # Step 9: Prepare the response to send back to the client
            # The response is encrypted and includes a MAC for integrity.
            response = json.dumps({"result": result}).encode()  # Serialize the result
            encrypted_response = encrypt(k_enc, response)  # Encrypt the response
            response_mac = generate_mac(k_mac, encrypted_response)  # Generate a MAC for the response
            conn.sendall(encrypted_response + response_mac)  # Send the encrypted response with the MAC


        except Exception as e:
            # Step 10: Handle errors and send an error response to the client
            # If an error occurs, send an encrypted error message with a MAC.
            error_msg = json.dumps({"result": str(e)}).encode()  # Serialize the error message
            encrypted_error = encrypt(k_enc, error_msg)  # Encrypt the error message
            error_mac = generate_mac(k_mac, encrypted_error)  # Generate a MAC for the error message
            conn.sendall(encrypted_error + error_mac)  # Send the encrypted error response with the MAC


def check_and_clear_logs():
    log_dir = "server/audit_logs"
    users = ["alice", "bob", "charlie"] #this can be changed and can use db to get a list fo suers so we dont ahve to update the users list each time 

    if not os.path.exists(log_dir):
        return  # No logs to check

    found_logs = []
    for user in users:
        log_path = os.path.join(log_dir, f"{user}.enc")
        if os.path.exists(log_path):
            found_logs.append(log_path)

    if found_logs:
        print("\nFound existing log files:")
        for log in found_logs:
            print(f"  - {log}")
        choice = input("\nDo you want to delete all logs and start fresh? (y/n): ").strip().lower()
        if choice == 'y':
            for log in found_logs:
                os.remove(log)
            print("All logs deleted.\n")
        else:
            print("Logs preserved.\n")


def main():
    check_and_clear_logs()  

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((HOST, PORT))
        server_socket.listen()
        server_socket.settimeout(1.0)  

        print(f"Bank Server listening on {HOST}:{PORT}")

        try:
            while True:
                try:
                    conn, addr = server_socket.accept()
                except socket.timeout:
                    continue  # loop back and check for KeyboardInterrupt

                thread = threading.Thread(target=client_thread, args=(conn, addr))
                thread.start()
                print(f"Active threads: {threading.active_count() - 1}")

        except KeyboardInterrupt:
            print("\nShutting down server...")
        finally:
            server_socket.close()

if __name__ == '__main__':
    main()
