import sqlite3
from db import get_db
from security import encrypt

username = input("Student username: ").strip()
roll_no = input("Roll number: ").strip()
full_name = input("Full name: ").strip()

conn = get_db()
user = conn.execute(
    "SELECT id, role FROM users WHERE username = ?", (username,)
).fetchone()

if not user or user["role"] != "student":
    print("Student user not found")
    conn.close()
    raise SystemExit

try:
    conn.execute(
        "INSERT INTO students (user_id, roll_no, full_name_enc) VALUES (?, ?, ?)",
        (user["id"], roll_no, encrypt(full_name)),
    )
    conn.commit()
    print("Student profile created!")
except sqlite3.IntegrityError:
    print("Profile or roll number already exists")
conn.close()