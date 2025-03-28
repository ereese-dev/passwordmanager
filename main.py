import os
import json
import base64
import argparse
import getpass

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

# Files to store the encrypted vault and the salt used for key derivation
VAULT_FILE = "vault.bin"
SALT_FILE = "salt.salt"

def load_salt():
    if os.path.exists(SALT_FILE):
        with open(SALT_FILE, "rb") as f:
            return f.read()
    else:
        salt = os.urandom(16)
        with open(SALT_FILE, "wb") as f:
            f.write(salt)
        return salt

def generate_key(master_password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
    return key

def load_vault(fernet):
    if not os.path.exists(VAULT_FILE):
        return {}
    
    with open(VAULT_FILE, "rb") as f:
        encrypted_data = f.read()
    
    try:
        decrypted_data = fernet.decrypt(encrypted_data)
        vault = json.loads(decrypted_data.decode())
        return vault
    except Exception:
        print("Failed to decrypt vault. Please check your master password or vault integrity.")
        exit(1)

def save_vault(vault, fernet):
    data = json.dumps(vault).encode()
    encrypted_data = fernet.encrypt(data)
    with open(VAULT_FILE, "wb") as f:
        f.write(encrypted_data)


salt = load_salt()
key  = generate_key("password", salt)
test_vault = {"YouMail": {"username": "me@youmail.com", "password": "password"}}
save_vault(test_vault, Fernet(generate_key("mypassword", salt)))
loaded_vault = load_vault(Fernet(generate_key("mypassword", salt)))
print(loaded_vault)