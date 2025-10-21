import os
import json
from base64 import b64encode, b64decode
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend


def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a 256-bit AES key from a user password and salt."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())


def encrypt_file(data: bytes, password: str) -> bytes:
    """Encrypt data using password-based AES-GCM."""
    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    encrypted = aesgcm.encrypt(nonce, data, None)

    # Store salt + nonce + ciphertext
    return salt + nonce + encrypted


def decrypt_file(encrypted_data: bytes, password: str) -> bytes:
    """Decrypt AES-GCM data using password."""
    salt = encrypted_data[:16]
    nonce = encrypted_data[16:28]
    ciphertext = encrypted_data[28:]
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)


def save_metadata(meta_path, filename):
    data = {"filename": filename}
    with open(meta_path, "w") as f:
        json.dump(data, f)


def load_meta(meta_path):
    if not os.path.exists(meta_path):
        return None
    with open(meta_path, "r") as f:
        return json.load(f)
