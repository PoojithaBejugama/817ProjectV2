import socket
import json
from auth_protocol import start_key_exchange
from key_derivation import derive_keys
from transaction_interface import transaction_loop

# =============================
# Point 1: ATM Client CLI
# Connects to the server and initiates login + secure session
# =============================

HOST = '127.0.0.1'
PORT = 65432

def main():
    print("\n=== Welcome to Secure ATM ===")
    username = input("Enter username: ")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))

        # Begin authenticated key exchange (Point 2)
        master_secret = start_key_exchange(s, username)

        # Derive keys for encryption and MAC (Point 3)
        k_enc, k_mac = derive_keys(master_secret)

        # Enter secure transaction loop (Point 4)
        transaction_loop(s, k_enc, k_mac)

if __name__ == '__main__':
    main()
