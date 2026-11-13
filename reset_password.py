import getpass
from db import get_db
from security import hash_password, is_strong_password

username = input("Username: ").strip()
password = getpass.getpass("New password: ")

if not is_strong_password(password):
    print("Weak password. Use 8+ chars with upper, lower, number and symbol.")
    raise SystemExit

conn = get_db()
cur = conn.execute(
    "UPDATE users SET password_hash = ?, failed_attempts = 0, locked_until = NULL WHERE username = ?",
    (hash_password(password), username),
)
conn.commit()
conn.close()
print("Password updated!" if cur.rowcount else "User not found")