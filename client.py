import socket
from Crypto.PublicKey import RSA, DSA
from Crypto.Signature import pkcs1_15, DSS
from Crypto.Hash import SHA256
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Util.Padding import pad, unpad
import base64
import tkinter as tk
from tkinter import simpledialog, messagebox
import threading

# Connection setup
PORT = 5051
SERVER = socket.gethostbyname(socket.gethostname())
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect((SERVER, PORT))

# Key generation and encoding
signature_type = simpledialog.askstring("Input", "Choose signature type (RSA/DSA):").strip().upper()
if signature_type == "DSA":
    key_pair = DSA.generate(2048)
    signer = DSS.new(key_pair, 'fips-186-3')
else:
    key_pair = RSA.generate(2048)
    signer = pkcs1_15.new(key_pair)

public_key = key_pair.publickey().export_key()
public_key_encoded = base64.b64encode(public_key)
client.send(f"{public_key_encoded.decode()}|{signature_type}".encode())

# Receive and decrypt session key
encrypted_session_key = base64.b64decode(client.recv(1024))
cipher_rsa = PKCS1_OAEP.new(key_pair)
session_key = cipher_rsa.decrypt(encrypted_session_key)

player_numbers = []
used_numbers = []

def sign_message(message, key_pair, signer):
    hash = SHA256.new(message.encode())
    signature = signer.sign(hash)
    return base64.b64encode(signature)

def encrypt_and_sign(message, key):
    cipher_aes = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher_aes.encrypt(pad(message.encode(), AES.block_size))
    encrypted_message = base64.b64encode(cipher_aes.iv + ct_bytes)
    signature = sign_message(message, key_pair, signer)
    return encrypted_message, signature

def decrypt(encrypted_message, key):
    encrypted_message = base64.b64decode(encrypted_message)
    iv = encrypted_message[:AES.block_size]
    ct = encrypted_message[AES.block_size:]
    cipher_aes = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher_aes.decrypt(ct), AES.block_size)
    return pt.decode()

def send_choice(choice):
    if choice.isdigit() and int(choice) in player_numbers and int(choice) not in used_numbers:
        used_numbers.append(int(choice))
        encrypted_message, signature = encrypt_and_sign(choice, session_key)
        choice_len = str(len(encrypted_message)).encode('utf-8')
        choice_len += b' ' * (1024 - len(choice_len))
        client.send(choice_len)
        client.send(encrypted_message)
        client.send(signature)
        response = decrypt(client.recv(1024), session_key)
        update_chat(response)
    else:
        messagebox.showerror("Invalid Choice", "Invalid choice or number already used")

def send_quit():
    encrypted_message, signature = encrypt_and_sign("quit", session_key)
    choice_len = str(len(encrypted_message)).encode('utf-8')
    choice_len += b' ' * (1024 - len(choice_len))
    client.send(choice_len)
    client.send(encrypted_message)
    client.send(signature)
    client.close()
    root.destroy()

def receive_message():
    while True:
        try:
            message = decrypt(client.recv(1024), session_key)
            update_chat(message)
            if message.startswith("Your numbers:"):
                global player_numbers
                player_numbers = list(map(int, message.split(": ")[1].strip('[]').split(', ')))
        except Exception as e:
            print(f"Error: {e}")
            break

def update_chat(message):
    chat_box.config(state=tk.NORMAL)
    chat_box.insert(tk.END, message + "\n")
    chat_box.config(state=tk.DISABLED)
    chat_box.see(tk.END)

def on_send():
    choice = entry.get()
    send_choice(choice)
    entry.delete(0, 'end')

# Tkinter GUI setup
root = tk.Tk()
root.title("Secure Poker Game")

header = tk.Label(root, text="Secure Poker Game", font=("Helvetica", 16, "bold"))
header.pack(pady=10)

chat_frame = tk.Frame(root)
chat_frame.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

chat_box = tk.Text(chat_frame, state=tk.DISABLED, wrap=tk.WORD)
chat_box.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

entry_frame = tk.Frame(root)
entry_frame.pack(pady=5)

entry = tk.Entry(entry_frame, font=("Helvetica", 12))
entry.grid(row=0, column=0, padx=5)

send_button = tk.Button(entry_frame, text="Send Choice", command=on_send, font=("Helvetica", 12))
send_button.grid(row=0, column=1, padx=5)

quit_button = tk.Button(root, text="Quit", command=send_quit, font=("Helvetica", 12))
quit_button.pack(pady=10)

# Start the thread to receive messages
threading.Thread(target=receive_message, daemon=True).start()

root.mainloop()
