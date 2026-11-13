import os
import re
import bcrypt
from cryptography.fernet import Fernet
from dotenv import load_dotenv

load_dotenv()
fernet = Fernet(os.environ["APP_KEY"].encode())


def hash_password(password: str) -> bytes:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())


def check_password(password: str, hashed: bytes) -> bool:
    return bcrypt.checkpw(password.encode(), hashed)


def is_strong_password(password: str) -> bool:
    return bool(
        len(password) >= 8
        and re.search(r"[A-Z]", password)
        and re.search(r"[a-z]", password)
        and re.search(r"\d", password)
        and re.search(r"[^A-Za-z0-9]", password)
    )


def encrypt(text: str) -> bytes:
    return fernet.encrypt(text.encode())


def decrypt(token: bytes) -> str:
    return fernet.decrypt(token).decode()