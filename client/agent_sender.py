from crypto_utils.crypto_module import encrypt_message
from Crypto.Random import get_random_bytes
from base32_utils.base32 import encode_base32
import dns.resolver
import math ,socket


LABEL_MAX = 63
CHUNK_SIZE = 30

def chunk_message(message: bytes, chunk_size: int = CHUNK_SIZE) -> list:
    chunks = []
    i = 0
    while i < len(message):
        chunk = message[i:i + chunk_size]
        chunks.append(chunk)
        i += chunk_size
    return chunks



def split_labels(encoded: str, max_len: int = LABEL_MAX) -> str:
    labels = []
    i = 0
    while i < len(encoded):
        label = encoded[i:i + max_len]
        labels.append(label)
        i += max_len
    return '.'.join(labels)




def build_domain(encoded: str, base_domain: str) -> str:
    labels = split_labels(encoded)
    return labels + '.' + base_domain




def build_payload(sequence: int, chunk: bytes, is_last: bool) -> bytes:
    sequence_str = f"{sequence:04d}|".encode()
    if is_last:
        return sequence_str + chunk + b"<END>"
    else:
        return sequence_str + chunk



def send_dns_query(domain: str):
    try:
        dns.resolver.resolve(domain, 'TXT')
        print("[✓] Sent:", domain)
    except Exception as e:
        print("[!] Failed:", domain, "→", e)


        

def send_chunked_message(message: bytes, key: bytes, base_domain: str):
    chunks = chunk_message(message)
    for index in range(len(chunks)):
        chunk = chunks[index]
        is_last = (index == len(chunks) - 1)
        payload = build_payload(index, chunk, is_last)
        encrypted = encrypt_message(payload, key)
        encoded = encode_base32(encrypted)
        domain = build_domain(encoded, base_domain)
        send_dns_query(domain)

if __name__ == "__main__":
    key = get_random_bytes(32)
    message = b"hello this is a test message to send securely over DNS tunnel"
    send_chunked_message(message, key, base_domain="tunnel.example.com")




# def send_dns_query(domain: str, server_ip="127.0.0.1", port=53535):
#     # ساختار ساده DNS query فقط برای TYPE=TXT
#     transaction_id = b'\xaa\xaa'  # شناسه دلخواه
#     flags = b'\x01\x00'           # standard query
#     qdcount = b'\x00\x01'         # 1 question
#     ancount = b'\x00\x00'
#     nscount = b'\x00\x00'
#     arcount = b'\x00\x00'
#     header = transaction_id + flags + qdcount + ancount + nscount + arcount

#     # ساخت QNAME
#     qname = b''
#     for part in domain.split('.'):
#         qname += bytes([len(part)]) + part.encode()
#     qname += b'\x00'  # پایان دامنه

#     qtype = b'\x00\x10'  # TXT record
#     qclass = b'\x00\x01' # IN class
#     question = qname + qtype + qclass

#     packet = header + question

#     sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
#     sock.sendto(packet, (server_ip, port))
#     try:
#         response, _ = sock.recvfrom(512)
#         print(f"[✓] Got response from {server_ip}:{port}")
#     except Exception as e:
#         print(f"[!] No response: {e}")




