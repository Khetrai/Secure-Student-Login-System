import sqlite3
import sys
import getpass
import pyotp
from db import get_db
from security import hash_password, is_strong_password

username = input("Username: ").strip()
role = input("Role (admin/teacher/student): ").strip().lower()

if role not in ("admin", "teacher", "student"):
    print("Invalid role")
    sys.exit()

password = getpass.getpass("Password: ")
if not is_strong_password(password):
    print("Weak password. Use 8+ chars with upper, lower, number and symbol.")
    sys.exit()

conn = get_db()
try:
    conn.execute(
        "INSERT INTO users (username, password_hash, role, otp_secret) VALUES (?, ?, ?, ?)",
        (username, hash_password(password), role, pyotp.random_base32()),
    )
    conn.commit()
    print(f"{role} '{username}' created!")
except sqlite3.IntegrityError:
    print("Username already exists")
conn.close()