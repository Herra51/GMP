import os
from Crypto.Cipher import AES
import base64
from dotenv import load_dotenv
from Crypto import Random
from Crypto.Util.Padding import pad, unpad

load_dotenv()

import base64

class PasswordGenerator:
    def __init__(self, key):
        self.bs = AES.block_size
        # Ensure the key is in bytes
        if isinstance(key, str):
            key = key.encode('utf-8')  # Convert string to bytes
        self.key = key  # Use the provided key as bytes

    def encrypt(self, raw):
        if isinstance(raw, str):  # Check if raw is a string
            raw = raw.encode()  # Encode to bytes if it's a string
        raw = pad(raw, self.bs)  # Use built-in padding
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw))

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(enc[AES.block_size:]), self.bs).decode('utf-8')