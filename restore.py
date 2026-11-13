import os
import shutil
import sqlite3
import sys
from datetime import datetime
from backup import BASE_DIR
from db import DATABASE

if len(sys.argv) != 2:
    print("Usage: python restore.py backups\\records_YYYYMMDD_HHMMSS.db")
    sys.exit()

src = sys.argv[1]
if not os.path.isfile(src):
    print("Backup file not found")
    sys.exit()

# backup healthy hai ya nahi
check = sqlite3.connect(src)
result = check.execute("PRAGMA integrity_check").fetchone()[0]
check.close()
if result != "ok":
    print("Backup is damaged:", result)
    sys.exit()

live = os.path.join(BASE_DIR, DATABASE)
if os.path.exists(live):
    safety = live + ".before_restore_" + datetime.now().strftime("%Y%m%d_%H%M%S")
    shutil.copy(live, safety)
    print("Current database saved as", safety)

shutil.copy(src, live)
print("Restore complete. Restart the app.")