import json

from utils import encrypt, decrypt, generate_mac, verify_mac


# ============================================================
# Point 4: Secure CLI Transaction Loop (Client Side)
# Sends encrypted and MAC-verified transactions to the server
# ============================================================


def transaction_loop(sock, k_enc, k_mac):
    while True:
        print("\nSelect an action:")
        print("1. Deposit")
        print("2. Withdraw")
        print("3. Check Balance")
        print("4. View My Logs")
        print("5. Exit")
        choice = input("Enter your choice: ")


        action = None
        data = {}


        if choice == '1':
            action = 'deposit'
            amount = int(input("Enter amount to deposit: "))
            data['amount'] = amount
        elif choice == '2':
            action = 'withdraw'
            amount = int(input("Enter amount to withdraw: "))
            data['amount'] = amount
        elif choice == '3':
            action = 'balance'
        elif choice == '4':
            action = 'view_log'
        elif choice == '5':
            print("\nLogging out.")
            break
        else:
            print("Invalid choice")
            continue


        data['action'] = action
        payload = json.dumps(data).encode()
        encrypted_payload = encrypt(k_enc, payload)
        mac = generate_mac(k_mac, encrypted_payload)


        # Send encrypted message with MAC
        sock.sendall(encrypted_payload + mac)


        # Receive and validate response
        response_packet = sock.recv(4096)
        encrypted_response = response_packet[:-32]
        received_mac = response_packet[-32:]


        if not verify_mac(k_mac, encrypted_response, received_mac):
            print("Integrity check failed. Possible tampering.")
            break


        decrypted_response = decrypt(k_enc, encrypted_response)
        result = json.loads(decrypted_response.decode())
        print("[Message from Server]:", result['result'])
