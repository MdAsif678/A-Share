import os 
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidTag

# AES-256 requires a 32-byte key
KEY_SIZE = 32

NONCE_SIZE = 12

PBKDF2_Iterations = 600_000

def generate_key() -> bytes:
    """Generate a cyptographically secure random 256 bit key."""
    return os.urandom(KEY_SIZE)

def generate_salt() -> bytes:
    """Generate a 16 byte random salt for password hashing"""
    return os.urandom(16)

def derive_key_from_password(password: str,salt:bytes)->bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=PBKDF2_Iterations
    )

    return kdf.derive(password.encode("utf-8"))

def encrypt_bytes(data: bytes,key: bytes) -> bytes:
    """
    Encrypts raw bytes using AES-256 GCM.
    Returns: nonce (12 bytes) + ciphertext + authentication tag(16 bytes) 
    """

    nonce = os.urandom(NONCE_SIZE)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce,data,None)
    return nonce + ciphertext

def decrypt_bytes(encrypted_data: bytes, key: bytes) -> bytes:
    """
    Decrypts AES-256-GCM encrypted bytes.
    Raises InvalidTag if the data was tampered with or the wrong key was supplied.
    """

    if len(encrypted_data) < NONCE_SIZE + 16:
        raise ValueError("Encrypted data is too short or malformed")

    nonce = encrypted_data[:NONCE_SIZE]
    ciphertext = encrypted_data[NONCE_SIZE:]

    aesgcm = AESGCM(key)
    #This will automatically raise InvalidTag if ciphertext or tag has been tampered with
    return aesgcm.decrypt(nonce, ciphertext, None)