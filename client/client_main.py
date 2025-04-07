import socket
import json
from auth_protocol import start_key_exchange
from key_derivation import derive_keys
from transaction_interface import transaction_loop


# ===========================================================
# Point 1: ATM Client 
# Connects to the server and initiates login + secure session
# ===========================================================


HOST = '127.0.0.1'  
PORT = 65432        


def main():
    print("\n=== Welcome to Secure ATM ===\n")
    username = input("Enter username: ")  
#get password here too
    #password = input("Enter password: ")  # Prompt for password

    # Create a TCP socket and connect to the server
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))  # Establish a connection to the server


        # Begin authenticated key exchange (Point 2)
        # This step establishes a shared Master Secret (MS) between the client and server
        master_secret = start_key_exchange(s, username) #send password here too


        # Derive keys for encryption and MAC (Point 3)
        # Using the Master Secret (MS), derive separate keys for encryption (k_enc) and message authentication (k_mac)
        k_enc, k_mac = derive_keys(master_secret)


        # Enter secure transaction loop (Point 4)
        # This loop handles secure communication with the server for transactions
        transaction_loop(s, k_enc, k_mac)


if __name__ == '__main__':
    main()  # Entry point of the program
