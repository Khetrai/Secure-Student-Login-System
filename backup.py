import os
import sqlite3
from datetime import datetime
from db import DATABASE

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
BACKUP_DIR = os.path.join(BASE_DIR, "backups")
KEEP = 10  # newest 10 backups rakhe jayenge


def list_backups():
    if not os.path.isdir(BACKUP_DIR):
        return []
    names = [f for f in os.listdir(BACKUP_DIR)
             if f.startswith("records_") and f.endswith(".db")]
    return sorted(names, reverse=True)


def backup_database():
    os.makedirs(BACKUP_DIR, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(BACKUP_DIR, f"records_{stamp}.db")

    src = sqlite3.connect(os.path.join(BASE_DIR, DATABASE))
    dst = sqlite3.connect(path)
    src.backup(dst)
    dst.close()
    src.close()

    for old in list_backups()[KEEP:]:
        os.remove(os.path.join(BACKUP_DIR, old))
    return path