import bcrypt
import sqlite3
import pandas as pd
from constants import DB_FILE
from validation import validate_string_input, validate_password

def hash_password(pw):
    return bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()

def check_password(pw, hashed):
    return bcrypt.checkpw(pw.encode(), hashed.encode())

def login(username, password, consent):
    # Input Validation for Login (Mitigates Bypass/Injection)
    username_sanit, err = validate_string_input(username, max_length=20)
    if err:
        return False, err
    pw_valid, pw_err = validate_password(password)
    if not pw_valid:
        return False, pw_err
    if not consent:
        return False, "Consent required (RA 10173/FERPA)"
    # Query DB directly for login
    conn = sqlite3.connect(DB_FILE)
    user_row = pd.read_sql_query("SELECT * FROM users WHERE username = ? AND active = 1", conn, params=[username_sanit])
    conn.close()
    if not user_row.empty and check_password(password, user_row.iloc[0]['password_hash']):
        return True, {
            'username': username_sanit,
            'role': user_row.iloc[0]['role']
        }
    return False, "Invalid login"

def register_user(username, password, role='student', students_df=None):
    """Registration Form Function (Simple: Validate/hash/add to users_df; demo auto-student role)."""
    username_sanit, u_err = validate_string_input(username, max_length=20)
    if u_err:
        return False, u_err
    pw_valid, p_err = validate_password(password)
    if not pw_valid:  # Fixed: Check pw_valid, not p_err directly
        return False, p_err
    # Check if exists in DB
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT 1 FROM users WHERE username = ?", (username_sanit,))
    if cursor.fetchone():
        conn.close()
        return False, "Username exists."
    conn.close()
    new_h = hash_password(password)
    new_sid = len(students_df) + 1 if students_df is not None and role == 'student' else None
    new_row = {'username': username_sanit, 'password_hash': new_h, 'role': role, 'student_id': new_sid, 'active': True}
    from database import save_user
    save_user(new_row)
    return True, "Registered! Login now."