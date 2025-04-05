# Secure Banking System - Project 2025

This project simulates a secure banking system with multiple ATM clients and a central bank server, implementing authentication, encryption, integrity checks, and audit logging.

## 🔧 Features
- Multithreaded Python bank server
- Authenticated key exchange with mutual authentication
- Key derivation (encryption + MAC)
- Encrypted transactions and integrity verification
- Encrypted audit logs
- GUI interfaces for both ATM clients and the bank server

---

## 📁 Folder Structure
```
secure_banking_system/
│
├── backend/
│   ├── auth_protocol.py         # Authenticated key distribution
│   ├── key_derivation.py        # Derives encryption & MAC keys from Master Secret
│   ├── transaction_protocol.py  # Secure message handling with encryption and HMAC
│   ├── audit_log.py             # Encrypted audit logging module
│
├── atm_gui_client.py           # Tkinter-based GUI ATM client
├── bank_server_gui.py          # Tkinter-based GUI bank server
├── audit_logs/
│   └── logs.enc                 # Encrypted audit log file
├── README.md                   # Setup instructions and project overview
├── requirements.txt            # Python dependencies
```

---

## 🚀 How to Run the Project

### 1. 📦 Install Dependencies
```bash
pip install pycryptodome
```

### 2. 🏦 Start the Bank Server GUI
```bash
python bank_server_gui.py
```
- A window will open to log incoming connections and activities.

### 3. 💳 Start One or More ATM Clients
```bash
python atm_gui_client.py
```
- Run this command multiple times in separate terminals to simulate multiple ATMs.
- Each will prompt for a username and open a GUI for transactions.

---

## 🛠️ Development Notes
- **All communication is encrypted using AES-CBC**.
- **MACs (HMAC-SHA256) ensure data integrity**.
- The system uses a **pre-shared key** to bootstrap the key exchange protocol.
- **Logs are stored encrypted** in `audit_logs/logs.enc`.

---

## 🧪 Demo Instructions
1. Start server: `python bank_server_gui.py`
2. Run 2–3 ATM clients: `python atm_gui_client.py`
3. Try Deposit, Withdraw, and Balance Inquiry
4. Check audit log (`logs.enc`) via `decrypt_log_file()` function in `audit_log.py`

---

## 📅 Submission
Submit the full project folder and report on D2L by **April 12, 2025**.

---

## 👥 Group Info
- Add group member names and IDs in your final report.

---

## 📄 License
For academic use only.
