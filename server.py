import socket
import threading
import signal
import sys
import random
from Crypto.PublicKey import RSA, DSA
from Crypto.Signature import pkcs1_15, DSS
from Crypto.Hash import SHA256
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64

PORT = 5051
SERVER = socket.gethostbyname(socket.gethostname())
ADDR = (SERVER, PORT)
END_MESSAGE = "quit"

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(ADDR)

players = []
player_numbers = {}
player_choices = {1: [], 2: []}
session_keys = {}
public_keys = {}
signature_types = {}
round_wins = {1: 0, 2: 0}
lock = threading.Lock()

def generate_unique_numbers():
    return random.sample(range(1, 16), 3)

def handle_player(conn, addr, player_id):
    print(f"[NEW CONNECTION] {addr} connected.")
    players.append(conn)

    rsa_public_key_encoded, sig_type = conn.recv(1024).decode().split("|")
    if sig_type == "DSA":
        rsa_public_key = DSA.import_key(base64.b64decode(rsa_public_key_encoded))
    else:
        rsa_public_key = RSA.import_key(base64.b64decode(rsa_public_key_encoded))
    public_keys[player_id] = rsa_public_key
    signature_types[player_id] = sig_type

    cipher_rsa = PKCS1_OAEP.new(rsa_public_key)
    session_key = get_random_bytes(16)
    session_keys[player_id] = session_key
    encrypted_session_key = cipher_rsa.encrypt(session_key)
    conn.send(base64.b64encode(encrypted_session_key))

    connected = True
    while connected:
        if player_id not in player_numbers:
            numbers = generate_unique_numbers()
            player_numbers[player_id] = numbers
            conn.send(encrypt(f"Your numbers: {numbers}", session_key))

        msg_length = conn.recv(1024).decode('utf-8')
        if msg_length:
            msg_length = int(msg_length.strip())
            encrypted_msg = conn.recv(msg_length)
            signature = conn.recv(1024)
            msg = decrypt(encrypted_msg, session_key)
            if verify_signature(msg, signature, public_keys[player_id], signature_types[player_id]):
                if msg == END_MESSAGE:
                    connected = False
                    print(f"[DISCONNECTED] {addr} disconnected.")
                    other_player_id = 1 if player_id == 2 else 2
                    announce_game_winner(player_id, other_player_id)
                    break
                elif msg.isdigit() and int(msg) in player_numbers[player_id] and int(msg) not in player_choices[player_id]:
                    print(f"[Player {player_id} played] {msg}")
                    with lock:
                        player_choices[player_id].append(int(msg))
                    conn.send(encrypt('Choice received', session_key))
                    if wait_for_moves():
                        break
                else:
                    conn.send(encrypt('Invalid choice or number already used', session_key))
            else:
                print(f"[ERROR] Invalid signature from player {player_id}")
                conn.send(encrypt('Invalid signature', session_key))
                connected = False

    conn.close()

def announce_round_winner():
    choice1 = player_choices[1][-1]
    choice2 = player_choices[2][-1]

    if choice1 > choice2:
        round_wins[1] += 1
    elif choice2 > choice1:
        round_wins[2] += 1

    for player_id, player in enumerate(players, 1):
        player.send(encrypt(f"Round results: Player 1 chose {choice1}, Player 2 chose {choice2}", session_keys[player_id]))

def wait_for_moves():
    with lock:
        if len(player_choices[1]) == len(player_choices[2]):
            announce_round_winner()
            if len(player_choices[1]) == 3 and len(player_choices[2]) == 3:
                announce_game_winner(None, None)
                return True
            return False
        return True

def announce_game_winner(disconnected_player_id, other_player_id):
    if disconnected_player_id:
        game_winner = f"Player {other_player_id} wins the game because Player {disconnected_player_id} disconnected!"
    else:
        if round_wins[1] > round_wins[2]:
            game_winner = "Player 1 wins the game!"
        elif round_wins[2] > round_wins[1]:
            game_winner = "Player 2 wins the game!"
        else:
            game_winner = "The game is a draw!"

    for player_id, player in enumerate(players, 1):
        if player_id in session_keys:
            player.send(encrypt(game_winner, session_keys[player_id]))

    for player in players:
        player.close()

    players.clear()
    player_numbers.clear()
    player_choices[1].clear()
    player_choices[2].clear()
    session_keys.clear()
    public_keys.clear()
    signature_types.clear()
    round_wins[1] = 0
    round_wins[2] = 0

def encrypt(message, key):
    cipher_aes = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher_aes.encrypt(pad(message.encode(), AES.block_size))
    return base64.b64encode(cipher_aes.iv + ct_bytes)

def decrypt(encrypted_message, key):
    encrypted_message = base64.b64decode(encrypted_message)
    iv = encrypted_message[:AES.block_size]
    ct = encrypted_message[AES.block_size:]
    cipher_aes = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher_aes.decrypt(ct), AES.block_size)
    return pt.decode()

def sign_message(message, private_key, sig_type):
    hash = SHA256.new(message.encode())
    if sig_type == "DSA":
        signer = DSS.new(private_key, 'fips-186-3')
    else:
        signer = pkcs1_15.new(private_key)
    signature = signer.sign(hash)
    return base64.b64encode(signature)

def verify_signature(message, signature, public_key, sig_type):
    try:
        hash = SHA256.new(message.encode())
        if sig_type == "DSA":
            verifier = DSS.new(public_key, 'fips-186-3')
        else:
            verifier = pkcs1_15.new(public_key)
        verifier.verify(hash, base64.b64decode(signature))
        return True
    except (ValueError, TypeError):
        return False

def signal_handler(sig, frame):
    print('Shutting down server...')
    for player in players:
        player.close()
    server.close()
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

def start():
    server.listen()
    print(f"[LISTENING] Server is listening on {SERVER}")
    while len(players) < 2:
        conn, addr = server.accept()
        player_id = len(players) + 1
        thread = threading.Thread(target=handle_player, args=(conn, addr, player_id))
        thread.start()
        print(f'[PLAYERS CONNECTED] {threading.active_count() - 1}')

print("[STARTING] Game server starting...")
start()
