import socket
import threading
import getpass
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os

class ChatClient:
    def __init__(self):
        # Prompt for server address and port
        host = input("Enter server address (e.g., '127.0.0.1'): ")
        port = int(input("Enter server port (e.g., 5555): "))

        # Establish socket connection
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_socket.connect((host, port))

        # Prompt for user details
        self.username = input("Enter your name: ")
        self.password = getpass.getpass("Enter encryption password: ")
        self.key = self.derive_key(self.password)

        # Send the username unencrypted
        self.client_socket.send(self.username.encode())

    def derive_key(self, password):
        """Derives a 32-byte key from the password."""
        salt = b'\x00' * 16  # Fixed salt for simplicity (should ideally be unique)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        return kdf.derive(password.encode())

    def encrypt_message(self, message):
        """Encrypts the message with AES."""
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(self.key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_message = iv + encryptor.update(message.encode()) + encryptor.finalize()
        return encrypted_message

    def decrypt_message(self, encrypted_message):
        """Decrypts the incoming AES-encrypted message."""
        iv = encrypted_message[:16]
        cipher = Cipher(algorithms.AES(self.key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_message = decryptor.update(encrypted_message[16:]) + decryptor.finalize()
        return decrypted_message.decode()

    def receive_messages(self):
        """Receive and decrypt messages from the server."""
        while True:
            try:
                data = self.client_socket.recv(1024)
                if not data:
                    break

                # Separate username and message
                username, encrypted_message = data.split(b": ", 1)

                # Attempt decryption, handle errors
                try:
                    message = self.decrypt_message(encrypted_message)
                    print(f"{username.decode('utf-8')}: {message}")
                except Exception:
                    print(f"Decryption failed for message from {username.decode('utf-8')}. Incorrect password or corrupted message.")

            except Exception as e:
                print(f"Connection error: {e}")
                break

    def send_messages(self):
        """Encrypt and send messages to the server."""
        while True:
            message = input("")
            if message.lower() == "exit":
                self.client_socket.close()
                break
            encrypted_message = self.encrypt_message(message)
            self.client_socket.send(encrypted_message)

    def run(self):
        """Run the client by starting sender and receiver threads."""
        threading.Thread(target=self.receive_messages, daemon=True).start()
        self.send_messages()

if __name__ == "__main__":
    client = ChatClient()
    client.run()
