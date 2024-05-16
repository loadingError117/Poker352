# Configuration settings for the Online Poker Game

# Network Configuration
HOST = 'localhost'  # IP address of the server
PORT = 12345        # Port number for the server
BUFFER_SIZE = 1024  # Buffer size for network communications

# Cryptographic Settings
RSA_KEY_SIZE = 2048         # Key size for RSA
DSA_KEY_SIZE = 2048         # Key size for DSA
SYM_KEY_SIZE = 256          # Symmetric key size (AES 256-bit)
PUBLIC_KEY_FORMAT = 'PEM'   # Format for storing public keys
PRIVATE_KEY_FORMAT = 'PEM'  # Format for storing private keys

# Game Settings
MAX_PLAYERS = 2             # Maximum number of players in a game session
NUMBER_RANGE = (1, 15)      # Range of numbers each player can receive
ROUNDS = 3                  # Number of rounds per game

# File Paths for Keys (assuming keys are stored in the root directory of the project)
SERVER_PRIVATE_KEY_PATH = 'server_private_key.pem'
SERVER_PUBLIC_KEY_PATH = 'server_public_key.pem'
PLAYER1_PRIVATE_KEY_PATH = 'player1_private_key.pem'
PLAYER1_PUBLIC_KEY_PATH = 'player1_public_key.pem'
PLAYER2_PRIVATE_KEY_PATH = 'player2_private_key.pem'
PLAYER2_PUBLIC_KEY_PATH = 'player2_public_key.pem'

# Security and Compliance
USE_SECURE_CONNECTION = True  # Toggle to require secure connections
LOGGING_LEVEL = 'DEBUG'       # Logging level
