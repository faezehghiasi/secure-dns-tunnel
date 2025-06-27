# Secure DNS Tunnel

This project implements a DNS tunneling system for secure and covert data transmission. Data is encrypted, chunked, and sent as DNS TXT record queries, which are then reconstructed on the server side. The system is designed for educational purposes, CTF challenges, or environments where standard communication channels are restricted, but DNS traffic is permitted.

---

## Features

* **End-to-End Encryption:** Data is encrypted with a shared AES key before being sent over the tunnel.
* **DNS TXT Channel:** Data is split, encoded in base32, and transmitted using DNS TXT queries, making detection harder.
* **Chunking:** Long messages are broken into chunks that respect DNS label and packet size limits.
* **Automatic Retry:** Each DNS query is resent up to 3 times on timeout or no-answer.
* **Fully Custom Server:** Server listens on port 53 (UDP), reconstructs the message, and sends back chunk-based ACKs as TXT answers.

---

## Project Structure

```
secure-dns-tunnel/
├── client/
│   └── agent_sender.py
├── server/
│   └── dns.py
├── crypto_utils/
│   └── crypto_module.py
├── base32_utils/
│   └── base32.py
├── README.md
└── ...
```

---

## How It Works

1. **Client Side:**

   * Input data is split into 30-byte chunks.
   * Each chunk is encrypted (AES) and base32-encoded.
   * Chunks are packed as subdomains of a base domain (e.g., `tunnel.example.com`).
   * Each chunk is sent as a DNS TXT query to the local DNS server (127.0.0.1:53).
   * On error or timeout, up to 3 retries are performed.

2. **Server Side:**

   * Listens on UDP port 53 for DNS queries.
   * Parses and decodes each chunk, decrypts, and stores them by sequence number.
   * Once all chunks received (last chunk has `<END>`), the full message is reassembled and printed.
   * Responds to each query with a TXT record containing an acknowledgment (ACK) for the sequence.

---

## Requirements

* Python 3.7+
* [dnspython](https://www.dnspython.org/) (client)
* [pycryptodome](https://pycryptodome.readthedocs.io/) (crypto)

```
pip install dnspython pycryptodome
```

---

## Usage

### 1. Prepare virtualenv

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt  # or install manually: dnspython pycryptodome
```

### 2. Run the server

**(A) Recommended (non-root):**
Give your Python binary permission to bind to port 53:

```bash
sudo setcap 'cap_net_bind_service=+ep' $(readlink -f ./venv/bin/python)
./venv/bin/python -m server.dns
```

**(B) Or run with sudo (not recommended):**

```bash
sudo ./venv/bin/python -m server.dns
```

### 3. Run the client

Open another terminal, activate venv, then run:

```bash
python -m client.agent_sender
```

---

## Configuration

* **Base Domain:** The domain used for tunneling can be set in the client code (e.g., `tunnel.example.com`).
* **Shared Key:** The shared AES key is defined in both client and server code. Change it for your use.

---

## Security Notes

* This tool is **not intended for production or malicious use**. It is for research, pentest labs, and learning only.
* All data is encrypted before transmission, but do **not** consider this bulletproof against advanced traffic analysis.

---

## Limitations & TODO

* Only UDP DNS supported
* No support for DNS compression pointers (yet)
* Currently only tested on localhost/127.0.0.1
* Base domain must be a valid DNS name and not blocked by your DNS server

---

## Example Output

**Server:**

```
[✓] DNS Tunnel Server is running on port 53
[+] Received DNS query from ('127.0.0.1', 54111)
[INFO] Chunk received: seq=0000 content=hello this is a test...
[✓] Full message reconstructed:
hello this is a test message to send securely over DNS tunnel using chunking and encryption methods to ensure that the message is transmitted correctly and securely without exceeding DNS label limits.
```

**Client:**

```
[INFO] acknowledgment received for sequence: 0000
[INFO] acknowledgment received for sequence: 0001
...
```


