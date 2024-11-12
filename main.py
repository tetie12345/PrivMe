import curses as c
import socket
import threading
import getpass
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os

class ChatClient:
    line = 0
    def __init__(self):
        # Prompt for server address and port
        host = getPromptedInput(1, 0, "Enter server ip (e.g., 127.0.0.1):")
        port = int(getPromptedInput(2, 0, "Enter server port (e.g., 5555): "))

        # Establish socket connection
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_socket.connect((host, port))

        self.connectedHost = host
        self.connectedPort = port

        # Prompt for user details
        self.username = getPromptedInput(3, 0, "Enter your name: ")
        self.password = getPromptedInput(4, 0, "Enter encryption password: ")
        self.key = self.derive_key(self.password)

        # Send the username unencrypted
        self.client_socket.send(self.username.encode())

        self.line = 0

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
                    username = username.decode('utf-8')
                    msg = f"{username}: {message}"
                    displayText(5+self.line, 2, msg)
                    self.line+=1
                except Exception as e:
                   print(e)

            except Exception as e:
                print(f"Connection error: {e}")
                break

    def send_messages(self):
        """Encrypt and send messages to the server."""
        while True:
            message = getInput(2, 15)
            if message.lower() == "exit":
                self.client_socket.close()
                break
            encrypted_message = self.encrypt_message(message)
            self.client_socket.send(encrypted_message)
            displayText(5+self.line, 2, f"you: {message}")
            self.line += 1

    def run(self):
        """Run the client by starting sender and receiver threads."""
        threading.Thread(target=self.receive_messages, daemon=True).start()
        self.send_messages()

#------------------------------------------------------------------------------
#------------------------------------------------------------------------------
screen = c.initscr()
c.noecho()
c.cbreak()
screen.keypad(True)


def getInput(screenPositionY, screenPositionX):
    unusedKeys = ["KEY_DC", "KEY_UP", "KEY_DOWN", "KEY_LEFT", "KEY_RIGHT", "KEY_HOME", "KEY_PPAGE", "KEY_NPAGE", "KEY_IC", "KEY_END", "KEY_RESIZE"]
    message = ""
    y, x = screenPositionY, screenPositionX
    maxSize = screen.getmaxyx()

    if x >= maxSize[1] or y >= maxSize[0]:
        raise ValueError(f"cannot write outside or on screen borders: {maxSize!r}")

    while (1):
        key = screen.getkey()
        keyw = key

        if key == "\n":
            return(message)

        if key in unusedKeys: continue

        if key == "KEY_BACKSPACE" or key == "\b" or key == chr(127):
            x-=1
            if x < screenPositionY: x = screenPositionY
            keyw = " "
            message = message[:-1]

        screen.addstr(y, x, keyw)


        if key != "KEY_BACKSPACE" and key != "\b" and key != chr(127):
            x+=1
            message += keyw

def getPromptedInput(screenPositionY, screenPositionX, prompt):
    displayText(screenPositionY, screenPositionX, prompt)
    return getInput(screenPositionY, screenPositionX+len(prompt)+1)

def displayText(screenPositionY, screenPositionX, text):
    screen.addstr(screenPositionY, screenPositionX, text)
    screen.refresh()

def screenSetup(connection):
    screen.clear()
    if screen.getmaxyx()[1] >= 50:
        displayText(0, screen.getmaxyx()[1]-14, "PRIVME TUI V1")

    if connection == 1:
        displayText(0, 0, f"CONNECTED TO {app.connectedHost}:{app.connectedPort} as {app.username}")
        displayText(2, 0, "SEND MESSAGE:")

        for i in range(15):
            displayText(4, i, "_")
            displayText(5+i, 0, "|")

try:
    screenSetup(0)

    app = ChatClient()

    screenSetup(1)

    app.run()

finally:
    c.echo()
    screen.keypad(False)
    c.endwin()
