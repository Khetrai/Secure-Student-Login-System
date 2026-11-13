import pyotp
import qrcode
from db import get_db

username = input("Username: ").strip()

conn = get_db()
user = conn.execute(
    "SELECT otp_secret FROM users WHERE username = ?", (username,)
).fetchone()
conn.close()

if not user:
    print("User not found")
    raise SystemExit

uri = pyotp.TOTP(user["otp_secret"]).provisioning_uri(
    name=username, issuer_name="DUET Records"
)
qrcode.make(uri).save("qr.png")
print("qr.png saved. Scan it with the authenticator app, then DELETE the file.")