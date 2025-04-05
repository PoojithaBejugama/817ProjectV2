import os
import json
import time
from utils import encrypt, get_audit_key

# =============================
# Point 4: Encrypted Audit Logging
# Stores customer actions in a secure, encrypted audit file
# =============================

AUDIT_LOG_PATH = 'server/audit_log.enc'

def log_encrypted_action(customer_id, action, timestamp):
    audit_data = {
        'customer_id': customer_id,
        'action': action,
        'timestamp': timestamp
    }
    log_entry = json.dumps(audit_data).encode()

    # Encrypt audit entry
    k_audit = get_audit_key()
    encrypted_entry = encrypt(k_audit, log_entry)

    # Append to file
    with open(AUDIT_LOG_PATH, 'ab') as f:
        f.write(encrypted_entry + b'\n')
