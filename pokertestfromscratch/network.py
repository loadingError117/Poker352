import socket
import ssl
import config
from utils import setup_logging, validate_number_choice
import logging

def create_server_socket():
    """Create and return a server socket with SSL if enabled."""
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((config.HOST, config.PORT))
    server_socket.listen(config.MAX_PLAYERS)
    logging.info(f"Server listening on {config.HOST}:{config.PORT}")
    if config.USE_SECURE_CONNECTION:
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(certfile='cert.pem', keyfile='key.pem')  # Keys
        server_socket = context.wrap_socket(server_socket, server_side=True)
    return server_socket

def accept_client(server_socket):
    """Accept a client connection and return the client socket and address."""
    client_socket, addr = server_socket.accept()
    logging.info(f"Accepted connection from {addr}")
    return client_socket, addr

def create_client_socket():
    """Create and return a client socket connected to the server, with SSL if enabled."""
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if config.USE_SECURE_CONNECTION:
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        context.load_verify_locations('cert.pem')  # Keys
        client_socket = context.wrap_socket(client_socket, server_hostname=config.HOST)
    client_socket.connect((config.HOST, config.PORT))
    logging.info(f"Connected to server at {config.HOST}:{config.PORT}")
    return client_socket

def send_message(sock, message):
    """Send a message through the socket."""
    sock.sendall(message)
    logging.info("Message sent to the server/client.")

def receive_message(sock):
    """Receive a message from the socket."""
    message = sock.recv(config.BUFFER_SIZE)
    logging.info("Message received from the server/client.")
    return message

def close_socket(sock):
    """Close the specified socket."""
    sock.close()
    logging.info("Socket closed.")
