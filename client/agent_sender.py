from crypto_utils.crypto_module import encrypt_message
from base32_utils.base32 import encode_base32
import socket

SHARED_KEY = b'0123456789abcdef0123456789abcdef'

LABEL_MAX = 63
CHUNK_SIZE = 30

def chunk_message(message):
    result = []
    i = 0
    while i < len(message):
        result.append(message[i:i + CHUNK_SIZE])
        i += CHUNK_SIZE
    return result




def split_labels(encoded):
    result = []
    i = 0
    while i < len(encoded):
        result.append(encoded[i:i + LABEL_MAX])
        i += LABEL_MAX
    return result



def build_domain(encoded, base_domain):
    return '.'.join(split_labels(encoded)) + '.' + base_domain



def build_payload(sequence, chunk, is_last):
    prefix = f"{sequence:04d}|".encode()
    if is_last:
        return prefix + chunk + b"<END>"
    else:
        return prefix + chunk



def send_dns_query(domain, server_ip="127.0.0.1", port=53535):
    transaction_id = b'\xaa\xaa'
    flags = b'\x01\x00'
    qdcount = b'\x00\x01'
    header = transaction_id + flags + qdcount + b'\x00\x00\x00\x00\x00\x00'

    qname = b''
    for part in domain.split('.'):
        qname += bytes([len(part)]) + part.encode()
    qname += b'\x00'

    qtype = b'\x00\x10'
    qclass = b'\x00\x01'
    packet = header + qname + qtype + qclass

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2)
    sock.sendto(packet, (server_ip, port))
    try:
        response, _ = sock.recvfrom(512)
        print("[INFO] Acknowledgment received for sequence:", domain.split('.')[0][:4])
    except socket.timeout:
        print("[WARNING] No acknowledgment received for sequence:", domain.split('.')[0][:4])
    finally:
        sock.close()



def send_chunked_message(message, base_domain, server_ip="127.0.0.1", port=53535):
    chunks = chunk_message(message)
    for i in range(len(chunks)):
        payload = build_payload(i, chunks[i], i == len(chunks) - 1)
        encrypted = encrypt_message(payload, SHARED_KEY)
        encoded = encode_base32(encrypted)
        domain = build_domain(encoded, base_domain)
        send_dns_query(domain, server_ip, port)

if __name__ == "__main__":
    msg = b"hello this is a test message to send securely over DNS tunnel using chunking and encryption methods to ensure that the message is transmitted correctly and securely without exceeding DNS label limits."
    send_chunked_message(msg, base_domain="tunnel.example.com")