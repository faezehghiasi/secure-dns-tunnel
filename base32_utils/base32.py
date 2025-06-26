import base64

def encode_base32(data: bytes) -> str:
    return base64.b32encode(data).decode('utf-8').strip('=').lower()

def decode_base32(data_str: str) -> bytes:
    padding = '=' * ((8 - len(data_str) % 8) % 8)
    return base64.b32decode(data_str.upper() + padding)
