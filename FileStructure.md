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