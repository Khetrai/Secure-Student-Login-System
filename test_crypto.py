from security import encrypt, decrypt

secret = encrypt("85")
print("Encrypted:", secret)
print("Decrypted:", decrypt(secret))