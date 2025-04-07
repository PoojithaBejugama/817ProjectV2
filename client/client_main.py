import socket
import json
from auth_protocol import start_key_exchange
from key_derivation import derive_keys
from transaction_interface import transaction_loop


# ======================================
# Client Main Program
# Entry point for the Secure ATM Client
# ======================================


HOST = '127.0.0.1'  
PORT = 65432        


def main():
    """
    Main function to run the Secure ATM client.
    Handles user authentication, key exchange, and secure transactions.
    """
    print("\n=== Welcome to Secure ATM ===\n")  


    # Step 1: Establish a connection to the server
    # Create a TCP socket and connect to the server
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))  # Connect to the server at the specified HOST and PORT




        ################## Username and Password checks are being handled by serevr! ################## 
        # Step 2: Server-driven login prompts
        # The server sends prompts for username and password, and the client responds
        prompt = s.recv(1024).decode()  # Receive the "Enter username:" prompt
        print(prompt, end="")  # Display the prompt to the user
        username = input()  # Get the username from the user
        s.send(username.encode())  # Send the username to the server

        prompt = s.recv(1024).decode()  # Receive the "Enter password:" prompt
        print(prompt, end="")  # Display the prompt to the user
        password = input()  # Get the password from the user
        s.send(password.encode())  # Send the password to the server
        ################################################################################################




        # Step 3: Handle authentication response
        # The server responds with "AUTH_SUCCESS" or an error message
        response = s.recv(1024).decode()  # Receive the authentication response
        if response != "AUTH_SUCCESS":
            # If authentication fails, display an error and exit
            print("Authentication failed. Closing client.")
            return
        else:
            # If authentication succeeds, proceed to the next steps
            print("Authentication successful.")


        # Step 4: Perform authenticated key exchange
        # Establish a shared Master Secret (MS) with the server
        master_secret = start_key_exchange(s, username)


        # Step 5: Derive encryption and MAC keys
        # Use the Master Secret (MS) to derive keys for encryption (k_enc) and message authentication (k_mac)
        k_enc, k_mac = derive_keys(master_secret)


        # Step 6: Enter secure transaction loop
        # Start the transaction interface to handle secure operations (e.g., deposit, withdraw, balance inquiry)
        transaction_loop(s, k_enc, k_mac)


if __name__ == '__main__':
    # Entry point of the program
    # Run the main function when the script is executed
    main()