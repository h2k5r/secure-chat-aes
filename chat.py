import socket
import threading
import sys
import random
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

# Diffie-Hellman parameters (small for demo; use larger in production!)
DH_PRIME = 0xFFFFFFFB
DH_BASE = 5

def dh_generate_private():
    return random.randint(2, DH_PRIME - 2)

def dh_generate_public(private):
    return pow(DH_BASE, private, DH_PRIME)

def dh_generate_shared(peer_public, my_private):
    return pow(peer_public, my_private, DH_PRIME)

def derive_key(shared_secret):
    # Derive a 32-byte key from the shared secret (simple method for demo)
    return shared_secret.to_bytes(32, byteorder='big', signed=False)

def aes_encrypt(key, plaintext):
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    return iv + ciphertext

def aes_decrypt(key, ciphertext):
    iv = ciphertext[:16]
    enc = ciphertext[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(enc), AES.block_size)

def handle_connection(conn, addr, shared_key):
    try:
        while True:
            msg_len_data = conn.recv(4)
            if not msg_len_data:
                break
            msg_len = int.from_bytes(msg_len_data, 'big')
            data = b''
            while len(data) < msg_len:
                packet = conn.recv(msg_len - len(data))
                if not packet:
                    break
                data += packet
            if not data:
                break
            try:
                message = aes_decrypt(shared_key, data)
                print(f"\n[{addr[0]}:{addr[1]}] {message.decode()}\n> ", end='', flush=True)
            except Exception as e:
                print(f"\n[!] Decryption error: {e}")
    finally:
        conn.close()

def listen_for_connections(port, shared_key):
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind(('', port))
    server_sock.listen(5)
    print(f"[+] Listening for incoming connections on port {port}...")
    while True:
        conn, addr = server_sock.accept()
        threading.Thread(target=handle_connection, args=(conn, addr, shared_key), daemon=True).start()

def connect_and_chat(ip, port, shared_key):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((ip, port))
        print(f"[+] Connected to {ip}:{port}")
        while True:
            msg = input("> ").strip()
            if not msg:
                continue
            enc = aes_encrypt(shared_key, msg.encode())
            sock.sendall(len(enc).to_bytes(4, 'big') + enc)
    except Exception as e:
        print(f"[!] Connection error: {e}")
    finally:
        sock.close()

def perform_key_exchange(sock, is_initiator):
    my_private = dh_generate_private()
    my_public = dh_generate_public(my_private)

    if is_initiator:
        sock.sendall(my_public.to_bytes(32, 'big'))
        their_public = int.from_bytes(sock.recv(32), 'big')
    else:
        their_public = int.from_bytes(sock.recv(32), 'big')
        sock.sendall(my_public.to_bytes(32, 'big'))

    shared_secret = dh_generate_shared(their_public, my_private)
    key = derive_key(shared_secret)
    return key

def server_key_exchange_thread(port, shared_key_container):
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind(('', port))
    server_sock.listen(1)
    print(f"[+] Waiting for key exchange on port {port}...")
    conn, addr = server_sock.accept()
    key = perform_key_exchange(conn, is_initiator=False)
    shared_key_container.append(key)
    print(f"[+] Key exchange complete with {addr[0]}:{addr[1]}")
    conn.close()
    server_sock.close()

def client_key_exchange_thread(ip, port, shared_key_container):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((ip, port))
    key = perform_key_exchange(sock, is_initiator=True)
    shared_key_container.append(key)
    print(f"[+] Key exchange complete with {ip}:{port}")
    sock.close()

def main():
    print("=== Secure AES Chat ===")
    listen_port = int(input("Enter port to listen on: "))
    connect_ip = input("Enter IP to connect to (leave blank to skip): ").strip()
    connect_port = None
    if connect_ip:
        connect_port = int(input("Enter port to connect to: "))

    # Key exchange
    shared_key_container = []
    threads = []

    if connect_ip:
        t = threading.Thread(target=client_key_exchange_thread, args=(connect_ip, connect_port, shared_key_container))
        t.start()
        threads.append(t)
    t = threading.Thread(target=server_key_exchange_thread, args=(listen_port, shared_key_container))
    t.start()
    threads.append(t)

    # Wait for key exchange to complete
    while not shared_key_container:
        pass
    shared_key = shared_key_container[0]

    # Start server listening thread
    threading.Thread(target=listen_for_connections, args=(listen_port, shared_key), daemon=True).start()

    # Start client chat thread if needed
    if connect_ip:
        connect_and_chat(connect_ip, connect_port, shared_key)
    else:
        print("[*] Waiting for incoming messages. Press Ctrl+C to exit.")
        while True:
            pass

if __name__ == "__main__":
    main()
