Project_2025_CLI_Banking_System/
│
├── server/
│   ├── server_main.py           # Point 1: Socket server + multithreading
│   ├── auth_protocol.py         # Point 2: Authenticated key distribution
│   ├── key_derivation.py        # Point 3: Key derivation for encryption and MAC
│   ├── transaction_handler.py   # Point 4: Secure transaction protocol (deposit, withdraw, etc.)
│   ├── audit_log.py             # Point 4: Encrypted audit logging
│   └── utils.py                 # Shared cryptographic tools
│
├── client/
│   ├── client_main.py           # Point 1: CLI interface with login prompt
│   ├── auth_protocol.py         # Point 2: Auth protocol from client side
│   ├── key_derivation.py        # Point 3: Mirror key derivation logic
│   ├── transaction_interface.py # Point 4: Encrypted transaction submission and MAC check
│   └── utils.py                 # Client-side helpers
│
└── README.md                   # Step-by-step guide

# Secure Banking System (CLI Version)

This is a CLI-based secure banking system for COE817 Project 2025. It simulates secure communication between a central bank server and ATM clients using symmetric cryptography.

## 🔧 Setup

### 1. Install dependencies
```bash
pip install cryptography
```

### 2. Prepare user key file
Create a file named `user_keys.json` in the `server/` folder:
```json
{
  "alice": "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
  "bob":   "11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff"
}
```

## 🚀 Running the System

### 1. Start the Bank Server
```bash
python server/server_main.py
```

### 2. Start ATM Client (in another terminal)
```bash
python client/client_main.py
```

## 🔑 Security Protocol Summary

### 1. Authentication & Key Exchange
- Uses **pre-shared symmetric keys** (`K_ATM`) per user
- Mutual authentication with **nonce challenge-response**
- Master Secret derived using: `HMAC(K_ATM, nonce_c || nonce_s)`

### 2. Key Derivation
- From the Master Secret:
  - `k_enc = HMAC(master_secret, "encryption")`
  - `k_mac = HMAC(master_secret, "mac")`

### 3. Secure Communication
- AES-CBC encryption + HMAC-SHA256 for all data
- Transactions supported:
  - Deposit
  - Withdraw
  - Balance Inquiry

### 4. Encrypted Audit Log
- Actions are logged as:
  ```
  Customer ID     Action     Timestamp
  ```
- Log file: `server/audit_log.enc` (binary, encrypted)

## 🧪 Testing Tips
- Try logging in with different users from `user_keys.json`
- Perform multiple actions and inspect that encrypted logs grow

---

### 📁 Folder Structure Overview
See `project_structure.txt` for a full module breakdown.

---

### ✅ Covered Project Points
- Point 1: Multithreaded server + CLI clients
- Point 2: Authenticated key distribution protocol
- Point 3: Key derivation (Enc + MAC keys)
- Point 4: Secure encrypted transactions + audit logs
- Point 5: Replaced GUI with CLI for simplicity