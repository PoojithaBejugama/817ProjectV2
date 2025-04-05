import socket
import threading
from transaction_handler import handle_client

# =============================
# Point 1: Multithreaded Bank Server
# This server listens for incoming ATM client connections,
# and for each client, it spawns a new thread to handle their session securely.
# =============================

HOST = '127.0.0.1'  # Localhost for development
PORT = 65432        # Arbitrary non-privileged port

def client_thread(conn, addr):
    print(f"[+] Connected by {addr}")
    try:
        handle_client(conn)
    except Exception as e:
        print(f"[!] Error handling client {addr}: {e}")
    finally:
        conn.close()
        print(f"[-] Disconnected {addr}")

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((HOST, PORT))
        server_socket.listen()
        print(f"[*] Bank Server listening on {HOST}:{PORT}")

        while True:
            conn, addr = server_socket.accept()
            thread = threading.Thread(target=client_thread, args=(conn, addr))
            thread.start()
            print(f"[~] Active threads: {threading.active_count() - 1}")

if __name__ == '__main__':
    main()
