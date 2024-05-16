import logging
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import config

def setup_logging():
    """Set up logging for the application."""
    logging.basicConfig(level=config.LOGGING_LEVEL,
                        format='%(asctime)s - %(levelname)s - %(message)s',
                        datefmt='%Y-%m-%d %H:%M:%S')

def validate_number_choice(number):
    """Validate that the chosen number is within the allowed range."""
    if number < config.NUMBER_RANGE[0] or number > config.NUMBER_RANGE[1]:
        raise ValueError(f"Chosen number {number} is out of the allowed range {config.NUMBER_RANGE}.")
    return True

def generate_random_number():
    """Generate a secure random number within the specified range."""
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import serialization
    from os import urandom
    import random

    return random.SystemRandom().randint(*config.NUMBER_RANGE)

def verify_rsa_signature(public_key, signature, message):
    """
    Verify an RSA signature using the specified public key and message.
    """
    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        logging.error(f"Signature verification failed: {e}")
        return False

def verify_dsa_signature(public_key, signature, message):
    """
    Verify a DSA signature using the specified public key and message.
    """
    try:
        public_key.verify(
            signature,
            message,
            hashes.SHA256()
        )
        return True
    except Exception as e:
        logging.error(f"Signature verification failed: {e}")
        return False

def sign_data(private_key, data, signature_scheme="RSA"):
    """
    Sign data using the given private key and return the signature.
    """
    if signature_scheme == "RSA":
        signature = private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
    elif signature_scheme == "DSA":
        signature = private_key.sign(
            data,
            hashes.SHA256()
        )
    else:
        raise ValueError("Unsupported signature scheme")
    return signature

# Example usage of setup logging
setup_logging()
