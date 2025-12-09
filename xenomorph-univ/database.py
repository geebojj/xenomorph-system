import sqlite3
import pandas as pd
from constants import DB_FILE
from auth import hash_password  # Import for default users

def init_db():
    """Initialize SQLite database and create users table if not exists."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL,
            student_id INTEGER,
            active BOOLEAN NOT NULL
        )
    """)
    # Insert default users if table is empty
    cursor.execute("SELECT COUNT(*) FROM users")
    if cursor.fetchone()[0] == 0:
        default_users = [
            ('student1', hash_password('pass123'), 'student', 1, True),
            ('faculty1', hash_password('pass456'), 'faculty', None, True),
            ('registrar1', hash_password('pass789'), 'registrar', None, True),
            ('admin1', hash_password('pass000'), 'admin', None, True)
        ]
        cursor.executemany("INSERT INTO users VALUES (?, ?, ?, ?, ?)", default_users)
    conn.commit()
    conn.close()

def load_users_df():
    """Load users from DB into Pandas DF."""
    conn = sqlite3.connect(DB_FILE)
    df = pd.read_sql_query("SELECT * FROM users", conn)
    conn.close()
    return df

def save_user(new_row):
    """Insert new user into DB."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT OR IGNORE INTO users (username, password_hash, role, student_id, active)
        VALUES (?, ?, ?, ?, ?)
    """, (new_row['username'], new_row['password_hash'], new_row['role'], new_row['student_id'], new_row['active']))
    conn.commit()
    conn.close()

def update_user_active(username, active):
    """Update user active status in DB."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET active = ? WHERE username = ?", (active, username))
    conn.commit()
    conn.close()

def execute_sql_query(query):
    """Execute SQL query on the database and return results."""
    conn = sqlite3.connect(DB_FILE)
    try:
        df = pd.read_sql_query(query, conn)
        return df
    except Exception as e:
        return pd.DataFrame({'Error': [str(e)]})
    finally:
        conn.close()