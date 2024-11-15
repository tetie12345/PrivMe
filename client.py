import socket
import threading
import getpass
import os
import curses
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

client_version = 0.06

class ChatClient:
    def __init__(self):
        # Prompt for server address and port (address:port format or domain name) outside of curses
        server_input = input("Enter server address (e.g., '127.0.0.1:5555' or 'chatserver.com'): ")
        if ':' in server_input:
            host, port = server_input.split(':')
            port = int(port)
        else:
            host = server_input
            port = int(input("Enter server port (e.g., 5555): "))
        
        # Establish socket connection
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_socket.connect((host, port))

        # Send ping to get server version
        self.client_socket.send("VERSION".encode())
        server_response = self.client_socket.recv(1024).decode('utf-8')

        if server_response.startswith("VERSION:"):
            server_version = int(server_response.split(":")[1])
        else:
            print("Failed to retrieve server version.")
            self.client_socket.close()
            return
        
        if server_version == client_version:
            print("Server and client version are the same. Checksum passed.")
        else:
            print("Server and client version are not the same, server is on {server_version} and client is on {client_version}. You may experience (significant) bugs.")

        # Send ping to get server settings
        self.client_socket.send("UML".encode())
        server_response = self.client_socket.recv(1024).decode('utf-8')
        
        # Parse the character limit from the server response
        if server_response.startswith("USERNAME_MAX_LENGTH:"):
            self.username_max_length = int(server_response.split(":")[1])
            print(f"Server allows usernames up to {self.username_max_length} characters. Username can not be empty and can't include spaces.")
        else:
            print("Failed to retrieve server settings.")
            self.client_socket.close()
            return

        # Prompt for username within the limit
        while True:
            self.username = input("Enter your name: ")
            if 0 < len(self.username) <= self.username_max_length or " " in self.username:
                break
            print(f"Username invalid. Please have a maximum of {self.username_max_length} characters. Username can also not be empty or have spaces.")
        
        # Send the username to the server
        self.client_socket.send(self.username.encode())
        
        # Prompt for password and derive the encryption key
        self.password = getpass.getpass("Enter encryption password: ")
        self.key = self.derive_key(self.password)

    def derive_key(self, password):
        """Derives a 32-byte key from the password."""
        salt = b'\x00' * 16
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

    def setup_windows(self, stdscr):
        """Initialize the chat and input windows with curses and setup colors."""
        self.stdscr = stdscr
        curses.curs_set(0)  # Hide cursor for cleaner display
        curses.start_color()  # Enable color mode in curses

        # Define color pairs
        curses.init_pair(1, curses.COLOR_GREEN, curses.COLOR_BLACK)  # Green for usernames
        curses.init_pair(2, curses.COLOR_WHITE, curses.COLOR_BLACK)  # White for "You:" and other messages

        # Define chat and input windows based on terminal size
        self.height, self.width = self.stdscr.getmaxyx()
        self.chat_win = curses.newwin(self.height - 3, self.width, 0, 0)
        self.input_win = curses.newwin(3, self.width, self.height - 3, 0)

        # Enable scrolling in chat window
        self.chat_win.scrollok(True)
        self.chat_win.idlok(True)

    def display_message(self, username, message, user_color_pair):
        """Display incoming messages in the chat box with username in color."""
        # Display the username in the specified color
        self.chat_win.addstr(username, curses.color_pair(user_color_pair))
        self.chat_win.addstr(f": {message}\n", curses.color_pair(2))  # Message in white
        self.chat_win.refresh()

    def receive_messages(self):
        """Receive and decrypt messages from the server."""
        while True:
            try:
                data = self.client_socket.recv(1024)
                if not data:
                    break

                # Check if the data is a plaintext server message (e.g., starting with "SYSTEM:")
                if data.startswith(b"Server:"):
                    message = data.decode("utf-8").replace("Server:", "")
                    self.display_message("System", message, 2)
                else:
                    # Separate username and encrypted message
                    username, encrypted_message = data.split(b": ", 1)
                    try:
                        message = self.decrypt_message(encrypted_message)
                        # Display the username in green and message in white
                        self.display_message(username.decode('utf-8'), message, 1)
                    except Exception:
                        self.display_message("System", "Decryption failed for a message.", 2)
                    
            except Exception as e:
                self.display_message("System", f"Connection error: {e}", 2)
                break

    def send_messages(self):
        """Encrypt and send messages to the server."""
        while True:
            # Clear and refresh input window
            self.input_win.clear()
            self.input_win.addstr("You: ", curses.color_pair(2))
            self.input_win.refresh()

            # Capture user input in the input box
            curses.echo()
            message = self.input_win.getstr().decode("utf-8")
            curses.noecho()

            if message.lower() == "exit":
                self.client_socket.close()
                break

            # Display "You: message" in chat window after sending
            self.display_message("You", message, 2)

            # Encrypt and send the message
            encrypted_message = self.encrypt_message(message)
            self.client_socket.send(encrypted_message)

    def run_chat(self, stdscr):
        """Run the curses interface and start chat operations."""
        self.setup_windows(stdscr)
        
        # Start the receiver thread
        threading.Thread(target=self.receive_messages, daemon=True).start()
        
        # Run the message-sending loop in the main thread
        self.send_messages()

    def run(self):
        """Main entry point for starting the chat client."""
        curses.wrapper(self.run_chat)

if __name__ == "__main__":
    client = ChatClient()
    client.run()
