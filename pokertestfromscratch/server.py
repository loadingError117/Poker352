import socket
import threading
import json
from network import create_server_socket, accept_client, send_message, receive_message, close_socket
from crypto import symmetric_encrypt, symmetric_decrypt, generate_symmetric_key
from utils import setup_logging, generate_random_number
import config
import logging

class PokerServer:
    def __init__(self):
        self.server_socket = create_server_socket()
        self.clients = []
        self.session_keys = {}
        self.game_state = {'round': 0, 'scores': {}}

    def run(self):
        try:
            while True:
                client_socket, addr = accept_client(self.server_socket)
                threading.Thread(target=self.handle_client, args=(client_socket, addr)).start()
        except Exception as e:
            logging.error(f"An error occurred: {e}")
        finally:
            close_socket(self.server_socket)

    def handle_client(self, client_socket, addr):
        # Generate a session key for this client
        session_key = generate_symmetric_key()
        self.session_keys[addr] = session_key
        
        # Send the client their initial set of numbers
        numbers = [generate_random_number() for _ in range(3)]
        encrypted_numbers = symmetric_encrypt(json.dumps(numbers).encode(), session_key)
        send_message(client_socket, encrypted_numbers)

        # Handle game rounds
        self.game_state['scores'][addr] = 0
        for _ in range(config.ROUNDS):
            try:
                encrypted_choice = receive_message(client_socket)
                choice = int(symmetric_decrypt(encrypted_choice, session_key).decode())
                self.process_choice(addr, choice)
            except ValueError as e:
                logging.error(f"Error processing choice from {addr}: {e}")
                break
        
        # End of game, determine winner
        if self.check_winner():
            winner = max(self.game_state['scores'], key=self.game_state['scores'].get)
            logging.info(f"Player {winner} wins.")
        else:
            logging.info("It's a draw.")

        # Clean up
        close_socket(client_socket)
        del self.session_keys[addr]

    def process_choice(self, addr, choice):
        self.game_state['scores'][addr] += choice
        logging.info(f"Processed choice {choice} from {addr}")

    def check_winner(self):
        return len(set(self.game_state['scores'].values())) > 1

if __name__ == '__main__':
    setup_logging()
    server = PokerServer()
    logging.info("Starting server...")
    server.run()
