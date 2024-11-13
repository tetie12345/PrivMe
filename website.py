from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO, emit
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
import socket
import threading

# Flask application setup
app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
socketio = SocketIO(app)

# Chat server configuration
SERVER_HOST = '127.0.0.1'
SERVER_PORT = 5556
USERNAME_MAX_LENGTH = 20  # Maximum character limit for usernames

# Globals for client connection and encryption
client_socket = None
encryption_key = None
username = None

def derive_key(password):
    """Derives a 32-byte encryption key from the provided password."""
    salt = b'\x00' * 16  # Simple salt for KDF
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_message(message):
    """Encrypts a message with AES using the derived key."""
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(encryption_key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_message = iv + encryptor.update(message.encode()) + encryptor.finalize()
    return encrypted_message

def decrypt_message(encrypted_message):
    """Decrypts a message with AES using the derived key."""
    iv = encrypted_message[:16]
    cipher = Cipher(algorithms.AES(encryption_key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_message = decryptor.update(encrypted_message[16:]) + decryptor.finalize()
    return decrypted_message.decode()

def listen_to_server():
    """Listen to messages from the server and broadcast to the web client."""
    while True:
        try:
            data = client_socket.recv(1024)
            if data:
                # If SYSTEM message, send directly
                if data.startswith(b"Server:"):
                    socketio.emit('message', {'username': 'System', 'message': data.decode('utf-8')})
                else:
                    # Otherwise decrypt and display
                    username, encrypted_message = data.split(b": ", 1)
                    message = decrypt_message(encrypted_message)
                    socketio.emit('message', {'username': username.decode('utf-8'), 'message': message})
        except:
            socketio.emit('message', {'username': 'System', 'message': 'Disconnected from server.'})
            break

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/username_requirements")
def username_requirements():
    # Endpoint to provide username requirements to the front end
    return jsonify({
        "max_length": USERNAME_MAX_LENGTH,
        "no_spaces": True,
        "non_empty": True
    })

@socketio.on('join')
def handle_join(data):
    global client_socket, encryption_key, username
    
    # Get username and password, connect to the server
    username = data['username']
    password = data['password']
    
    # Validate username based on server requirements
    if not username or len(username) > USERNAME_MAX_LENGTH or " " in username:
        emit('message', {'username': 'System', 'message': f"Username must be 1-{USERNAME_MAX_LENGTH} characters long and contain no spaces."})
        return

    encryption_key = derive_key(password)
    
    # Set up the socket connection to the server
    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((SERVER_HOST, SERVER_PORT))
        client_socket.send("PING".encode())
        
        # Wait for USERNAME_MAX_LENGTH message from the server
        server_response = client_socket.recv(1024).decode('utf-8')
        
        # Send the username to the server
        client_socket.send(username.encode())
        
        # Start listening to the server in a new thread
        threading.Thread(target=listen_to_server, daemon=True).start()
        emit('message', {'username': 'System', 'message': f'You joined the chat as {username}.'})
    except Exception as e:
        emit('message', {'username': 'System', 'message': f'Failed to connect to server: {e}'})

@socketio.on('send_message')
def handle_send_message(data):
    message = data['message']
    encrypted_message = encrypt_message(message)
    client_socket.send(encrypted_message)
    emit('message', {'username': 'You', 'message': message}, broadcast=True)

if __name__ == "__main__":
    socketio.run(app, host='0.0.0.0', port=80)
