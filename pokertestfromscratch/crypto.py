from cryptography.hazmat.primitives.asymmetric import rsa, dsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
# from cryptography.hazmat.primitives.symmetric import AES, modes, Cipher
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding as sym_padding
from os import urandom

def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def generate_dsa_keys():
    private_key = dsa.generate_private_key(
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def save_private_key(private_key, filename):
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(filename, 'wb') as key_file:
        key_file.write(pem)

def save_public_key(public_key, filename):
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(filename, 'wb') as key_file:
        key_file.write(pem)

def load_private_key(filename):
    with open(filename, 'rb') as key_file:
        private_key = load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )
    return private_key

def load_public_key(filename):
    with open(filename, 'rb') as key_file:
        public_key = load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )
    return public_key

def encrypt_message(message, public_key):
    ciphertext = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

def decrypt_message(ciphertext, private_key):
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext

def sign_message(message, private_key, algorithm="RSA"):
    if algorithm == "RSA":
        signer = private_key.signer(
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
    elif algorithm == "DSA":
        signer = private_key.signer(hashes.SHA256())
    signer.update(message)
    return signer.finalize()

def verify_signature(message, signature, public_key, algorithm="RSA"):
    if algorithm == "RSA":
        verifier = public_key.verifier(
            signature,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
    elif algorithm == "DSA":
        verifier = public_key.verifier(signature, hashes.SHA256())
    verifier.update(message)
    verifier.verify()

def generate_symmetric_key():
    return urandom(32)  # Generates a 256-bit symmetric key

def symmetric_encrypt(message, key):
    iv = urandom(16)  # AES block size in CBC mode
    cipher = Cipher(AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = sym_padding.PKCS7(AES.block_size).padder()
    padded_data = padder.update(message) + padder.finalize()
    return iv + encryptor.update(padded_data) + encryptor.finalize()

def symmetric_decrypt(ciphertext, key):
    iv = ciphertext[:16]
    cipher = Cipher(AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    unpadder = sym_padding.PKCS7(AES.block_size).unpadder()
    return unpadder.update(decryptor.update(ciphertext[16:]) + decryptor.finalize()) + unpadder.finalize()
