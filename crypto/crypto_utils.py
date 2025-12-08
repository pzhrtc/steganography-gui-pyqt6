import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os

def encrypt_bytes(data: bytes, password: str) -> bytes:
    key = hashlib.sha256(password.encode()).digest()
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct = cipher.encrypt(pad(data, AES.block_size))
    return iv + ct

def decrypt_bytes(encrypted: bytes, password: str) -> bytes:
    key = hashlib.sha256(password.encode()).digest()
    iv = encrypted[:16]
    ct = encrypted[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), AES.block_size)
