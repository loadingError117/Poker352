import socket
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP, AES
from Cryptodome.Util.Padding import pad, unpad
import base64

PORT = 5051
END_MESSAGE = 'quit'
SERVER = socket.gethostbyname(socket.gethostname())

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect((SERVER, PORT))

key_pair = RSA.generate(bits=1024)
public_key = key_pair.publickey().export_key()
public_key_encoded = base64.b64encode(public_key)
client.send(public_key_encoded)

encrypted_session_key = base64.b64decode(client.recv(1024))
cipher_rsa = PKCS1_OAEP.new(key_pair)
session_key = cipher_rsa.decrypt(encrypted_session_key)

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

def send_choice(choice):
    encrypted_choice = encrypt(choice, session_key)
    choice_len = str(len(encrypted_choice)).encode('utf-8')
    choice_len += b' ' * (1024 - len(choice_len))
    client.send(choice_len)
    client.send(encrypted_choice)
    print(decrypt(client.recv(1024), session_key))

while True:
    print(decrypt(client.recv(1024), session_key))
    for _ in range(3):
        choice = input(f"Choose a number from your set: ")
        if choice == END_MESSAGE:
            send_choice(choice)
            client.send(encrypt(END_MESSAGE, session_key))
            client.close()
            exit()
        send_choice(choice)
        print(decrypt(client.recv(1024), session_key))
