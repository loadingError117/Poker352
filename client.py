import socket
from Crypto.PublicKey import RSA, DSA
from Crypto.Signature import pkcs1_15, DSS
from Crypto.Hash import SHA256
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Util.Padding import pad, unpad
import base64
import threading

# Connection setup
PORT = 5051
SERVER = socket.gethostbyname(socket.gethostname())
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    client.connect((SERVER, PORT))
except ConnectionRefusedError:
    print("Unable to connect to the server. Ensure the server is running and try again.")
    exit()

# Key generation and encoding
signature_type = input("Choose signature type (RSA/DSA): ").strip().upper()
while signature_type not in ["RSA", "DSA"]:
    signature_type = input("Invalid choice. Choose signature type (RSA/DSA): ").strip().upper()

if signature_type == "DSA":
    dsa_key_pair = DSA.generate(2048)
    signer = DSS.new(dsa_key_pair, 'fips-186-3')
    public_key = dsa_key_pair.publickey().export_key()
else:
    rsa_key_pair = RSA.generate(2048)
    signer = pkcs1_15.new(rsa_key_pair)
    public_key = rsa_key_pair.publickey().export_key()

client.send(f"{public_key.decode()}|{signature_type}".encode())

# Receive and decrypt session key
encrypted_session_key = base64.b64decode(client.recv(4096))
print("Length of encrypted session key:", len(encrypted_session_key))
print("Encrypted session key:", encrypted_session_key)

if signature_type == "DSA":
    session_key = encrypted_session_key
else:
    cipher_rsa = PKCS1_OAEP.new(rsa_key_pair)
    session_key = cipher_rsa.decrypt(encrypted_session_key)

assert len(session_key) == 16, "Session key length must be 16 bytes."

player_numbers = []
used_numbers = []

def sign_message(message, signer):
    hash = SHA256.new(message.encode())
    signature = signer.sign(hash)
    return base64.b64encode(signature)

def encrypt_and_sign(message, session_key, signer):
    cipher_aes = AES.new(session_key, AES.MODE_CBC)
    ct_bytes = cipher_aes.encrypt(pad(message.encode(), AES.block_size))
    encrypted_message = base64.b64encode(cipher_aes.iv + ct_bytes)
    signature = sign_message(message, signer)
    return encrypted_message, signature

def decrypt(encrypted_message, key):
    print("Decrypting...")
    print("Length of encrypted message:", len(encrypted_message))
    if len(encrypted_message) == 0:
        print("Empty encrypted message received.")
        return None
    try:
        encrypted_message = base64.b64decode(encrypted_message)
        print("Decoded message length:", len(encrypted_message))
        iv = encrypted_message[:AES.block_size]  # IV should be 16 bytes long
        if len(iv) != AES.block_size:
            print("Incorrect IV length:", len(iv))
            return None
        print("IV:", iv)
        ct = encrypted_message[AES.block_size:]
        print("Ciphertext:", ct)
        cipher_aes = AES.new(key, AES.MODE_CBC, iv)
        pt = unpad(cipher_aes.decrypt(ct), AES.block_size)
        print("Decrypted plaintext:", pt)
        return pt.decode()
    except Exception as e:
        print(f"Decryption error: {e}")
        return None

def receive_message():
    while True:
        try:
            encrypted_message = client.recv(1024)
            if not encrypted_message:
                print("No message received, closing connection.")
                break
            message = decrypt(encrypted_message, session_key)
            if message:
                if message.startswith("Your numbers:"):
                    numbers = message.split(": ")[1].strip("[]").split(', ')
                    player_numbers.extend(map(int, numbers))
                    print("Your numbers: " + ', '.join(numbers))
                else:
                    print(message)
            else:
                print("Received empty or invalid message")
        except Exception as e:
            print(f"Error: {e}")
            break

    print("Receiver thread exiting...")
    client.close()

def send_choice(choice):
    if choice.isdigit() and int(choice) in player_numbers and int(choice) not in used_numbers:
        used_numbers.append(int(choice))
        encrypted_message, signature = encrypt_and_sign(choice, session_key, signer)
        message_length = len(encrypted_message)
        choice_len = str(message_length).encode('utf-8')
        choice_len += b' ' * (1024 - len(choice_len))
        client.send(choice_len)
        client.send(encrypted_message)
        client.send(signature)
        response = decrypt(client.recv(1024), session_key)
        print(response)
    else:
        print("Invalid choice or number already used")

def send_quit():
    encrypted_message, signature = encrypt_and_sign("quit", session_key, signer)
    message_length = len(encrypted_message)
    choice_len = str(message_length).encode('utf-8')
    choice_len += b' ' * (1024 - len(choice_len))
    client.send(choice_len)
    client.send(encrypted_message)
    client.send(signature)
    client.close()

# Start the thread to receive messages
receiver_thread = threading.Thread(target=receive_message, daemon=True)
receiver_thread.start()

try:
    while True:
        choice = input("Enter your choice (or 'quit' to exit): ").strip()
        if choice.lower() == 'quit':
            send_quit()
            break
        else:
            send_choice(choice)
finally:
    receiver_thread.join()
    print("Client exiting...")
