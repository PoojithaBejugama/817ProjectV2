import os
import json
from utils import encrypt, get_audit_key


# =============================
# Point 4: Encrypted Audit Logging (Per User)
# Stores customer actions in separate encrypted files
# =============================


AUDIT_LOG_DIR = 'server/audit_logs'  # Directory to store encrypted audit logs

def log_encrypted_action(customer_id, action, timestamp):
    """
    Logs a customer's action in an encrypted audit log file.

    Parameters:
        customer_id (str): The unique identifier for the customer.
        action (str): The action performed by the customer (e.g., "deposit", "withdraw").
        timestamp (str): The timestamp of when the action occurred.

    Returns:
        None
    """


    # Step 1: Prepare the audit data
    # Create a dictionary containing the customer ID, action, and timestamp
    audit_data = {
        'customer_id': customer_id,
        'action': action,
        'timestamp': timestamp
    }


    # Step 2: Serialize the audit data to JSON and encrypt it
    log_entry = json.dumps(audit_data).encode()  
    encrypted_entry = encrypt(get_audit_key(), log_entry)  


    # Step 3: Ensure the audit_logs directory exists
    # Create the directory if it does not already exist
    os.makedirs(AUDIT_LOG_DIR, exist_ok=True)


    # Step 4: Determine the per-user log file path
    # Each customer has their own encrypted log file named <customer_id>.enc
    user_log_file = os.path.join(AUDIT_LOG_DIR, f"{customer_id}.enc")



    # Step 5: Append the encrypted log entry to the user's log file
    # Open the file in append-binary mode ('ab') to add the new entry
    with open(user_log_file, 'ab') as f:
        f.write(encrypted_entry + b'\n')  # Write the encrypted entry followed by a newline
        f.flush()  
        os.fsync(f.fileno())  




    # Debugging information
    print(f"\n[DEBUG] Logging for {customer_id}: {action} at {timestamp}")
    print(f"[DEBUG] Saving to file: {user_log_file}\n")