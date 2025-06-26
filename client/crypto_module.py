from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

def encrypt_message(plaintext: bytes, key: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return cipher.nonce + tag + ciphertext

def decrypt_message(payload: bytes, key: bytes) -> bytes:
    nonce = payload[:16]
    tag = payload[16:32]
    ciphertext = payload[32:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)
