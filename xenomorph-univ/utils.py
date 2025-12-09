import datetime
import pandas as pd
import io
import bcrypt
from constants import SESSION_TIMEOUT_SECONDS

def log_audit(audit_log_df, user, action):
    new_log = pd.DataFrame({
        'timestamp': [datetime.datetime.now()],
        'user': [user],
        'action': [action]
    })
    return pd.concat([audit_log_df, new_log], ignore_index=True)

def encrypt_sensitive(data):
    return bcrypt.hashpw(str(data).encode(), bcrypt.gensalt()).decode()[:16]

def xor_encrypt_decrypt(data, key):
    """Simple XOR demo: Reversible encryption/decryption with a key (for educational purposes; not secure for prod)."""
    data_bytes = str(data).encode('utf-8')
    key_bytes = str(key).encode('utf-8')
    key_length = len(key_bytes)
    result = bytearray()
    for i, byte in enumerate(data_bytes):
        result.append(byte ^ key_bytes[i % key_length])
    return result.decode('utf-8', errors='ignore')  # Decode back to string; same func for encrypt/decrypt

def check_session_timeout(login_time):
    if login_time and (datetime.datetime.now() - login_time).total_seconds() > SESSION_TIMEOUT_SECONDS:
        return True
    return False

@pd.api.extensions.register_dataframe_accessor("streamlit_export")
def export_to_csv(self, filename):
    csv_buffer = io.StringIO()
    self.to_csv(csv_buffer, index=False)
    return csv_buffer.getvalue(), filename