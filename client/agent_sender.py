from crypto_utils.crypto_module import encrypt_message
from base32_utils.base32 import encode_base32
import dns.resolver, dns.exception
import time

SHARED_KEY = b'0123456789abcdef0123456789abcdef'

LABEL_MAX = 63
CHUNK_SIZE = 30
MAX_RETRY = 3    
RETRY_DELAY = 0.5  #in second

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

def send_dns_query(domain):
    resolver = dns.resolver.Resolver()
    resolver.nameservers = ['127.0.0.1']
    resolver.port = 53

    tries = 0
    while tries < MAX_RETRY:
        try:
            answers = resolver.resolve(domain, "TXT", lifetime=2)
            print("[INFO] acknowledgment received for sequence:", domain.split('.')[0][:4])
            return True
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            print(f"[WARNING] no answer for seq: {domain.split('.')[0][:4]} (try {tries+1})")
        except dns.exception.Timeout:
            print(f"[WARNING] timeout for seq: {domain.split('.')[0][:4]} (try {tries+1})")
        tries += 1
        if tries < MAX_RETRY:
            time.sleep(RETRY_DELAY)
    print(f"[ERROR] failed to send seq: {domain.split('.')[0][:4]} after {MAX_RETRY} attempts.")
    return False

def send_chunked_message(message, base_domain):
    chunks = chunk_message(message)
    for i, chunk in enumerate(chunks):
        payload = build_payload(i, chunk, i == len(chunks) - 1)
        encrypted = encrypt_message(payload, SHARED_KEY)
        encoded = encode_base32(encrypted)
        domain = build_domain(encoded, base_domain)
        send_dns_query(domain)

if __name__ == "__main__":
    msg = b"hello this is a test message to send securely over DNS tunnel using chunking and encryption methods to ensure that the message is transmitted correctly and securely without exceeding DNS label limits."
    send_chunked_message(msg, base_domain="tunnel.example.com")
