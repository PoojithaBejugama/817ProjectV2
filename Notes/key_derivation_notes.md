Great! For Point 2 of the project — the Authenticated Key Distribution Protocol, here’s a simple, effective, and symmetric key-based approach that meets all your project’s requirements:

🔐 Protocol Choice: Mutual Authentication with a Pre-Shared Key (PSK)
We assume that each ATM client and the bank server already share a unique pre-shared key (K_ATM). This protocol ensures:

✅ Client authenticates the server

✅ Server authenticates the client

✅ A fresh Master Secret (MS) is securely established between them

✅ Replay protection using random nonces

📋 Protocol Steps (Symmetric-Key Based)
Here’s how the key exchange protocol works:

➤ Step 1: Client → Server
ClientHello = {username, nonce_c}
Client sends username and a random nonce (nonce_c)

➤ Step 2: Server → Client
ServerHello = ENC_K_ATM({nonce_c, nonce_s})
Server responds by encrypting the client’s nonce and a newly generated server nonce (nonce_s) using the pre-shared key K_ATM

This proves that the server knows the key

➤ Step 3: Client → Server
ClientResponse = ENC_K_ATM({nonce_s})
Client proves knowledge of K_ATM by correctly decrypting the previous message and echoing nonce_s back

✅ If the server receives the correct nonce_s, mutual authentication is complete.

🧪 Deriving the Master Secret
Once authentication is successful, both sides generate the Master Secret (MS) as:

MS = HMAC(K_ATM, nonce_c + nonce_s)
Where:

K_ATM = pre-shared key

nonce_c, nonce_s = random values from client and server

HMAC = cryptographically secure key derivation

This master secret is then used to derive:

🔐 K_enc: encryption key

🧾 K_mac: MAC key