import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad  # Import padding utilities
import base64
from dotenv import load_dotenv
from Crypto import Random

load_dotenv()

class PasswordGenerator:
    def __init__(self, key):
        self.bs = AES.block_size
        # Ensure the key is in bytes
        if isinstance(key, str):
            key = key.encode('utf-8')  # Convert string to bytes
        self.key = key

    def encrypt(self, raw):
        if isinstance(raw, str):  # Check if raw is a string
            raw = raw.encode()  # Encode to bytes if it's a string
        raw = pad(raw, self.bs)  # Use built-in padding
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw))

    def decrypt(self, encrypted):
        try:
            # Decode the base64-encoded input
            encrypted = base64.b64decode(encrypted)
            if len(encrypted) < self.bs:  # Ensure the data is long enough to contain an IV
                raise ValueError("Encrypted data is too short to contain a valid IV.")
            
            iv = encrypted[:self.bs]  # Extract the first 16 bytes as the IV
            cipher = AES.new(self.key, AES.MODE_CBC, iv)
            decrypted = cipher.decrypt(encrypted[self.bs:])  # Decrypt the remaining data
            return unpad(decrypted, self.bs)  # Use unpad to remove padding
        except Exception as e:
            raise ValueError(f"Error decrypting password: {str(e)}")