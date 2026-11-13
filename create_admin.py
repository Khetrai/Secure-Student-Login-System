import sys
import getpass
import pyotp
from db import get_db
from security import hash_password, is_strong_password

username = input("Admin username: ").strip()
password = getpass.getpass("Admin password: ")

if not is_strong_password(password):
    print("Weak password. Use 8+ chars with upper, lower, number and symbol.")
    sys.exit()

conn = get_db()
conn.execute(
    "INSERT INTO users (username, password_hash, role, otp_secret) VALUES (?, ?, ?, ?)",
    (username, hash_password(password), "admin", pyotp.random_base32()),
)
conn.commit()
conn.close()
print("Admin created!")