import os
from Crypto.Cipher import AES
import base64
from dotenv import load_dotenv
load_dotenv()

def encrypt_string(plain_text):
    key = os.getenv('ENCRYPTION_KEY').encode()
    if len(key) not in [16, 24, 32]:
        raise ValueError("Incorrect AES key length (%d bytes)" % len(key))
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(plain_text.encode())
    return base64.b64encode(nonce + ciphertext).decode('utf-8')

def decrypt_string(encrypted_text):
    key = os.getenv('ENCRYPTION_KEY').encode()
    if len(key) not in [16, 24, 32]:
        raise ValueError("Incorrect AES key length (%d bytes)" % len(key))
    encrypted_data = base64.b64decode(encrypted_text)
    nonce = encrypted_data[:16]
    ciphertext = encrypted_data[16:]
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    plain_text = cipher.decrypt(ciphertext).decode('utf-8')
    return plain_text

text = "mon&Mode1De5Passe"
encrypted = encrypt_string(text)
print(encrypted)
decrypted = decrypt_string(encrypted)
print(decrypted)



print(decrypt_string("gjMFp2KMl8IqEypl3VFWBoIF/R5SYrC2ImgOD9Hivi4B"))
print(decrypt_string("DkDS46EWLJbcO0Kluy/PFVfeqe+VkcfzObW8gokDHSoF"))
print(decrypt_string("cTCfgy15UYWmN3xmjVlpjj9KTp2Cdcwr0pDEtoDNJ3rU"))