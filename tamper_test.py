from db import get_db

conn = get_db()
row = conn.execute("SELECT action FROM audit_log WHERE id = 2").fetchone()
old = row["action"]

conn.execute("UPDATE audit_log SET action = 'HACKED' WHERE id = 2")
conn.commit()
input("Row 2 changed to HACKED. Refresh /audit in the browser (red warning), then press Enter to restore... ")

conn.execute("UPDATE audit_log SET action = ? WHERE id = 2", (old,))
conn.commit()
print("Restored")