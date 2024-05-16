PYTHON FILES EXPLAINATION

1. 'config.py':
    - Provides global configurations like network settings, cryptographic key sizes, and other constants.
    - Imported and used by nearly all other modules to ensure consistent configurations across the application.

2. 'crypto.py':
    - Handles all cryptographic operations including key generation, encryption, decryption, and signing.
    - Used by server.py and client.py for encrypting and decrypting messages, and by network.py if message encryption/decryption is handled at the network level.

3. 'utils.py':
    - Contains utility functions like logging setup, validation functions, and potentially any other helper functions needed across the application.
    - Used by 'server.py' and 'client.py' for tasks like setting up logging, validating inputs, and more.

4. 'network.py':
    - Manages all network communications including creating server and client sockets and sending/receiving messages.
    - Imported by 'server.py' for accepting client connections and managing communication, and by 'client.py' for connecting to the server and handling communication.

5. 'server.py':
    - Manages the server-side game logic and client connections.
    - Uses 'network.py' for network operations, 'crypto.py' for encrypting and decrypting messages, and 'utils.py' for logging and utility functions.

6. 'client.py':
    - Handles the client-side operations, communicating with the server, making game decisions, and displaying results.
    - Uses 'network.py' for network operations, 'crypto.py' for encrypting and decrypting messages, and 'utils.py' for logging and utility functions.


HOW TO RUN

Prerequisites:
1. Install Python 3
python.org
2. Install Dependencies: 'cryptography'
pip install cryptography
3. Setup SSL Certificate
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
4. Make sure IP address and port numbers in 'config.py' are correctly set for your network environment.

Running the server:
1. Open a terminal
2. Navigate to directory containing Python files
3. Run the server script (This will start the server, which will listen for incoming client connections on specified IP address and port)
python server.py

Running the client:
1. Open another terminal
2. Navigate to directory containing Python files
3. Run the client script (This will start the client and attempt to connect to the server at the configured IP address and port)
4. Follow prompts or directions output by the client script to interact with the game.