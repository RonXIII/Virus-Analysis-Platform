# profile_manager.py – Secure profile and API key storage
import os
import sqlite3
import hashlib
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

DB_PATH = os.path.join(os.path.dirname(__file__), "profiles.db")

def get_db_connection():
    """Get a connection to the SQLite database."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_database():
    """Create the database tables if they don't exist."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS profiles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS api_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            profile_id INTEGER NOT NULL,
            service TEXT NOT NULL,
            encrypted_key TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (profile_id) REFERENCES profiles(id) ON DELETE CASCADE,
            UNIQUE(profile_id, service)
        )
    ''')
    conn.commit()
    conn.close()

def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a Fernet key from a password and salt using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key_bytes = kdf.derive(password.encode('utf-8'))
    return base64.urlsafe_b64encode(key_bytes)

def create_profile(username: str, password: str) -> bool:
    """Create a new profile with the given username and password."""
    salt = os.urandom(16)
    key = derive_key(password, salt)
    password_hash = hashlib.sha256(key).hexdigest()

    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO profiles (username, password_hash, salt) VALUES (?, ?, ?)",
            (username, password_hash, salt.hex())
        )
        conn.commit()
        conn.close()
        return True
    except sqlite3.IntegrityError:
        conn.close()
        return False

def login(username: str, password: str):
    """Authenticate a user and return their profile data if successful."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM profiles WHERE username = ?", (username,))
    row = cursor.fetchone()
    conn.close()

    if not row:
        return None

    salt = bytes.fromhex(row['salt'])
    key = derive_key(password, salt)
    password_hash = hashlib.sha256(key).hexdigest()

    if password_hash == row['password_hash']:
        return {
            'id': row['id'],
            'username': row['username'],
            'key': key
        }
    return None

def get_api_keys(profile_id: int, key: bytes) -> dict:
    """Retrieve and decrypt all API keys for a profile."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT service, encrypted_key FROM api_keys WHERE profile_id = ?", (profile_id,))
    rows = cursor.fetchall()
    conn.close()

    fernet = Fernet(key)
    result = {}
    for row in rows:
        try:
            decrypted = fernet.decrypt(row['encrypted_key'].encode('utf-8'))
            result[row['service']] = decrypted.decode('utf-8')
        except:
            continue
    return result

def save_api_key(profile_id: int, service: str, key: bytes, value: str) -> bool:
    """Encrypt and save an API key for a profile."""
    fernet = Fernet(key)
    encrypted = fernet.encrypt(value.encode('utf-8')).decode('utf-8')

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO api_keys (profile_id, service, encrypted_key)
        VALUES (?, ?, ?)
        ON CONFLICT(profile_id, service) DO UPDATE SET
            encrypted_key = excluded.encrypted_key,
            updated_at = CURRENT_TIMESTAMP
    ''', (profile_id, service, encrypted))
    conn.commit()
    conn.close()
    return True

def delete_api_key(profile_id: int, service: str) -> bool:
    """Delete an API key for a profile."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM api_keys WHERE profile_id = ? AND service = ?", (profile_id, service))
    conn.commit()
    conn.close()
    return True

def delete_profile(profile_id: int) -> bool:
    """Delete a profile and all its API keys (cascades)."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM profiles WHERE id = ?", (profile_id,))
    conn.commit()
    conn.close()
    return True

def get_all_services(profile_id: int) -> list:
    """Get a list of all service names for a profile."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT service FROM api_keys WHERE profile_id = ?", (profile_id,))
    rows = cursor.fetchall()
    conn.close()
    return [row['service'] for row in rows]

# Initialize the database on module import
init_database()