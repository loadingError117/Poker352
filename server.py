import socket
import threading
import random
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP, AES
from Cryptodome.Util.Padding import pad, unpad
from Cryptodome.Random import get_random_bytes
import base64

PORT = 5051
SERVER = socket.gethostbyname(socket.gethostname())
ADDR = (SERVER, PORT)
END_MESSAGE = "quit"

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(ADDR)

players = []
player_numbers = {}
player_choices = {1: [], 2: []}
session_keys = {}
lock = threading.Lock()

def handle_player(conn, addr, player_id):
    print(f"[NEW CONNECTION] {addr} connected.")
    players.append(conn)

    rsa_public_key_encoded = conn.recv(1024)
    rsa_public_key = RSA.import_key(base64.b64decode(rsa_public_key_encoded))
    cipher_rsa = PKCS1_OAEP.new(rsa_public_key)

    session_key = get_random_bytes(16)
    session_keys[player_id] = session_key
    encrypted_session_key = cipher_rsa.encrypt(session_key)
    conn.send(base64.b64encode(encrypted_session_key))

    connected = True
    while connected:
        if player_id not in player_numbers:
            numbers = [random.randint(1, 15) for _ in range(3)]
            player_numbers[player_id] = numbers
            conn.send(encrypt(f"Your numbers: {numbers}", session_key))

        for _ in range(3):
            msg_length = conn.recv(1024).decode('utf-8')
            if msg_length:
                msg_length = int(msg_length.strip())
                encrypted_msg = conn.recv(msg_length)
                msg = decrypt(encrypted_msg, session_key)
                if msg == END_MESSAGE:
                    connected = False
                    print(f"[DISCONNECTED] {addr} disconnected.")
                    other_player_id = 1 if player_id == 2 else 2
                    announce_game_winner(player_id, other_player_id)
                    break
                else:
                    if msg.isdigit():
                        print(f"[Player {player_id} played] {msg}")
                        with lock:
                            player_choices[player_id].append(int(msg))
                        conn.send(encrypt('Choice received', session_key))
                    else:
                        print(f"[Player {player_id} disconnected] {msg}")
                        connected = False
                        other_player_id = 1 if player_id == 2 else 2
                        announce_game_winner(player_id, other_player_id)
                        break
                    if wait_for_moves():
                        break
        if not connected:
            break

    conn.close()

def announce_round_winner():
    choice1 = player_choices[1][-1]
    choice2 = player_choices[2][-1]

    if choice1 > choice2:
        round_winner = "Player 1 wins this round!"
    elif choice2 > choice1:
        round_winner = "Player 2 wins this round!"
    else:
        round_winner = "This round is a draw!"

    for player_id, player in enumerate(players, 1):
        player.send(encrypt(round_winner, session_keys[player_id]))

def wait_for_moves():
    with lock:
        if len(player_choices[1]) == len(player_choices[2]):
            announce_round_winner()
            if len(player_choices[1]) == 3 and len(player_choices[2]) == 3:
                for player_id in player_numbers:
                    player_numbers[player_id] = [random.randint(1, 15) for _ in range(3)]
                    players[player_id - 1].send(encrypt(f"New numbers: {player_numbers[player_id]}", session_keys[player_id]))
                player_choices[1].clear()
                player_choices[2].clear()
            return False
        return True

def announce_game_winner(disconnected_player_id, other_player_id):
    if disconnected_player_id:
        game_winner = f"Player {other_player_id} wins the game because Player {disconnected_player_id} disconnected!"
    else:
        choice1_sum = sum(player_choices[1])
        choice2_sum = sum(player_choices[2])
        if choice1_sum > choice2_sum:
            game_winner = "Player 1 wins the game!"
        elif choice2_sum > choice1_sum:
            game_winner = "Player 2 wins the game!"
        else:
            game_winner = "The game is a draw!"

    for player_id, player in enumerate(players, 1):
        if player_id in session_keys:
            player.send(encrypt(game_winner, session_keys[player_id]))

    # Close the connection for the other player
    for player in players:
        player.close()

    # Clear the lists and dictionaries
    players.clear()
    player_numbers.clear()
    player_choices[1].clear()
    player_choices[2].clear()
    session_keys.clear()

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
