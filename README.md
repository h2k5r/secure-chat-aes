# Secure AES Chat Application with Diffie-Hellman Key Exchange

## Overview

This Python application enables secure, real-time text chat between two users over a network. It uses:
- **Diffie-Hellman key exchange** to securely establish a shared secret key between peers, even over an insecure network.
- **AES (Advanced Encryption Standard) in CBC mode** for encrypting all chat messages, ensuring confidentiality.
- **Concurrent server and client functionality**: Each instance can both listen for incoming connections and connect out to another peer, allowing two-way communication.

No sensitive key material is ever sent over the network in plaintext. All encryption and decryption use the shared secret established via Diffie-Hellman.

---

## How It Works

1. **Startup**:  
   - Each user runs the script on their machine.
   - Each user chooses a port to listen on.
   - Optionally, a user can enter the IP address and port of another user to connect to.

2. **Key Exchange**:  
   - When two users connect, they perform a Diffie-Hellman key exchange to derive a shared AES encryption key.
   - This key is never transmitted—only public values are exchanged, and the key is computed independently on both sides.

3. **Messaging**:  
   - All messages are encrypted using AES (CBC mode, with a random IV per message).
   - Messages are sent and received over TCP sockets.
   - Each user can send and receive messages concurrently.

4. **Security**:  
   - The shared key is used for all encryption/decryption.
   - Each message uses a new random IV for strong security.

---

## Requirements

- Python 3.6 or higher
- [pycryptodome](https://pypi.org/project/pycryptodome/) library

Install dependencies with:
```bash
pip install pycryptodome
```

---

## How to Run

1. **Save the script** (provided above) as `secure_chat.py`.

2. **Open a terminal/command prompt** on each computer.

3. **Run the script**:
   ```bash
   python secure_chat.py
   ```

4. **Follow the prompts**:
   - Enter a port to listen on (e.g., `5000`).
   - If you want to connect to another user, enter their IP and port. If not, just press Enter.

5. **Key Exchange**:
   - The program will automatically perform a Diffie-Hellman key exchange when a connection is made.

6. **Start Chatting**:
   - Type messages and press Enter to send.
   - Incoming messages will appear in the terminal.

**Note:** For two-way chat, at least one user should enter the other's IP and port to initiate a connection. Both users can also try connecting to each other for redundancy.

---

## Example Usage

**User 1 (listening):**
```
Enter port to listen on: 5000
Enter IP to connect to (leave blank to skip):
[*] Waiting for incoming messages. Press Ctrl+C to exit.
```

**User 2 (connecting):**
```
Enter port to listen on: 5001
Enter IP to connect to (leave blank to skip): 192.168.1.10
Enter port to connect to: 5000
[+] Connected to 192.168.1.10:5000
> Hello!
```

---

## Features

- End-to-end encryption using AES with a key derived from Diffie-Hellman exchange
- No need for pre-shared keys
- Works on local networks or over the internet (with correct port forwarding)
- Concurrent server and client operation in a single script

---

## Security Notes

- For demonstration purposes, Diffie-Hellman parameters are small; for production, use larger, standardized primes.
- This script does not authenticate peers or verify message integrity (no HMAC). For production, add authentication and integrity checks.
- Only text messages are supported.

---

## References

- [AES and Diffie-Hellman in secure chat applications][1][2][3][5]
- [pycryptodome documentation](https://pycryptodome.readthedocs.io/)

