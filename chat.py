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

class SecureChat:
    def __init__(self):
        self.shared_key = None
        self.connections = []
        self.running = True
        self.nickname = input("Enter your nickname: ").strip() or "Anonymous"

    def handle_incoming_connection(self, conn, addr):
        """Handle incoming messages from a connected peer"""
        try:
            while self.running:
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
                    message = aes_decrypt(self.shared_key, data)
                    print(f"\n[{addr[0]}:{addr[1]}] {message.decode()}")
                    print(f"[{self.nickname}] ", end='', flush=True)
                except Exception as e:
                    print(f"\n[!] Decryption error: {e}")
        except Exception as e:
            print(f"\n[!] Connection error with {addr}: {e}")
        finally:
            conn.close()
            if conn in self.connections:
                self.connections.remove(conn)

    def listen_for_connections(self, port):
        """Listen for incoming connections"""
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            server_sock.bind(('', port))
            server_sock.listen(5)
            print(f"[+] Listening for incoming connections on port {port}...")
            while self.running:
                try:
                    conn, addr = server_sock.accept()
                    print(f"[+] New connection from {addr[0]}:{addr[1]}")
                    self.connections.append(conn)
                    threading.Thread(target=self.handle_incoming_connection, 
                                   args=(conn, addr), daemon=True).start()
                except Exception as e:
                    if self.running:
                        print(f"[!] Error accepting connection: {e}")
        except Exception as e:
            print(f"[!] Error setting up server: {e}")
        finally:
            server_sock.close()

    def send_messages(self):
        """Handle outgoing messages"""
        print(f"\n[*] You can now start chatting! Type 'quit' to exit.")
        while self.running:
            try:
                msg = input(f"[{self.nickname}] ").strip()
                if msg.lower() == 'quit':
                    self.running = False
                    break
                if not msg:
                    continue
                
                # Send message to all connected peers
                if self.connections:
                    full_message = f"{self.nickname}: {msg}"
                    enc = aes_encrypt(self.shared_key, full_message.encode())
                    message_data = len(enc).to_bytes(4, 'big') + enc
                    
                    for conn in self.connections[:]:  # Copy list to avoid modification during iteration
                        try:
                            conn.sendall(message_data)
                        except Exception as e:
                            print(f"[!] Failed to send to a peer: {e}")
                            self.connections.remove(conn)
                else:
                    print("[!] No active connections. Waiting for peers to connect...")
            except KeyboardInterrupt:
                self.running = False
                break
            except Exception as e:
                print(f"[!] Error sending message: {e}")

    def connect_to_peer(self, ip, port):
        """Connect to a peer"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((ip, port))
            print(f"[+] Connected to {ip}:{port}")
            self.connections.append(sock)
            
            # Start receiving messages from this connection
            threading.Thread(target=self.handle_incoming_connection, 
                           args=(sock, (ip, port)), daemon=True).start()
            return True
        except Exception as e:
            print(f"[!] Failed to connect to {ip}:{port}: {e}")
            return False

    def perform_key_exchange(self, sock, is_initiator):
        """Perform Diffie-Hellman key exchange"""
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

    def server_key_exchange_thread(self, port, shared_key_container):
        """Handle key exchange as server"""
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            server_sock.bind(('', port))
            server_sock.listen(1)
            print(f"[+] Waiting for key exchange on port {port}...")
            conn, addr = server_sock.accept()
            key = self.perform_key_exchange(conn, is_initiator=False)
            shared_key_container.append(key)
            print(f"[+] Key exchange complete with {addr[0]}:{addr[1]}")
            conn.close()
        finally:
            server_sock.close()

    def client_key_exchange_thread(self, ip, port, shared_key_container):
        """Handle key exchange as client"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((ip, port))
            key = self.perform_key_exchange(sock, is_initiator=True)
            shared_key_container.append(key)
            print(f"[+] Key exchange complete with {ip}:{port}")
            sock.close()
        except Exception as e:
            print(f"[!] Key exchange failed: {e}")

    def start_chat(self):
        """Main chat function"""
        print("=== Secure AES Chat ===")
        listen_port = int(input("Enter port to listen on: "))
        connect_ip = input("Enter IP to connect to (leave blank to skip): ").strip()
        connect_port = None
        if connect_ip:
            connect_port = int(input("Enter port to connect to: "))

        # Key exchange
        shared_key_container = []
        threads = []

        # Start key exchange threads
        if connect_ip:
            t = threading.Thread(target=self.client_key_exchange_thread, 
                               args=(connect_ip, connect_port, shared_key_container))
            t.start()
            threads.append(t)
        
        t = threading.Thread(target=self.server_key_exchange_thread, 
                           args=(listen_port, shared_key_container))
        t.start()
        threads.append(t)

        # Wait for key exchange to complete
        print("[*] Performing key exchange...")
        while not shared_key_container:
            pass
        self.shared_key = shared_key_container[0]
        print("[+] Secure key established!")

        # Start listening for incoming connections
        threading.Thread(target=self.listen_for_connections, 
                        args=(listen_port,), daemon=True).start()

        # Connect to peer if specified
        if connect_ip:
            # Small delay to ensure both sides are ready
            import time
            time.sleep(1)
            self.connect_to_peer(connect_ip, connect_port)

        # Start the message sending interface
        try:
            self.send_messages()
        except KeyboardInterrupt:
            pass
        finally:
            self.running = False
            print("\n[*] Shutting down...")
            for conn in self.connections:
                conn.close()

def main():
    chat = SecureChat()
    chat.start_chat()

if __name__ == "__main__":
    main()
