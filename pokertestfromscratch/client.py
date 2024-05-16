import socket
import json
from network import create_client_socket, send_message, receive_message, close_socket
from crypto import symmetric_encrypt, symmetric_decrypt, generate_symmetric_key
from utils import setup_logging
import config
import logging

class PokerClient:
    def __init__(self):
        self.client_socket = create_client_socket()
        self.session_key = generate_symmetric_key()  # Assume client generates and shares a symmetric key securely

    def start(self):
        try:
            # Receive the initial set of numbers from the server
            encrypted_numbers = receive_message(self.client_socket)
            numbers = json.loads(symmetric_decrypt(encrypted_numbers, self.session_key).decode())
            logging.info(f"Received numbers: {numbers}")

            # Interact with the user to select numbers for each round
            for _ in range(config.ROUNDS):
                choice = self.choose_number(numbers)
                encrypted_choice = symmetric_encrypt(str(choice).encode(), self.session_key)
                send_message(self.client_socket, encrypted_choice)

            # Optionally, wait to receive game results from the server
            # (This part depends on whether the server sends such a message)
            # result = receive_message(self.client_socket)
            # logging.info(f"Game result: {result.decode()}")

        except Exception as e:
            logging.error(f"An error occurred during game play: {e}")
        finally:
            close_socket(self.client_socket)

    def choose_number(self, numbers):
        """Allow the user to choose a number from the given list."""
        while True:
            try:
                choice = int(input(f"Choose one of these numbers {numbers}: "))
                if choice in numbers:
                    return choice
                logging.error("Invalid choice. Please choose a number from the list.")
            except ValueError:
                logging.error("Invalid input. Please enter a valid number.")

if __name__ == '__main__':
    setup_logging()
    client = PokerClient()
    logging.info("Client started. Connecting to server...")
    client.start()
