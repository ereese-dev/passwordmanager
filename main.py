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

def add_entry(args, vault, fernet):
    name = args.name
    if name in vault:
        print(f"Entry '{name}' already exists.")
        return
    
    vault[name] = {
        "username": args.username,
        "password": args.password
    }
    save_vault(vault, fernet)
    print(f"Entry '{name}' added successfully.")

def get_entry(args, vault):
    name = args.name
    if name not in vault:
        print(f"Entry '{name}' not found.")
        return
    
    entry = vault[name]
    print(f"Entry '{name}':")
    print(f"Username: {entry['username']}")
    print(f"Password: {entry['password']}")

def list_entries(args, vault):
    if not vault:
        print("Vault is empty.")
        return
    
    print ("Stored entries:")
    for name in vault:
        print(f"- {name}")

def main():
    parser = argparse.ArgumentParser(description="CLI Password Manager")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    #Command to add a new entry
    parser_add = subparsers.add.parser("add", help="Add a new credential")
    parser_add.add_argument("name", help="Unique name for the credential")
    parser_add.add_argument("username", help="Username for the credential")
    parser_add.add_argument("password", help="Password for the credential")

    #Command to retrieve credential
    parser_get = subparsers.add_parser("get", help="Retrieve a credential")
    parser_get.add_argument("name", help="Name of the credential to retrieve")

    #Command to list all credential names in the vault
    subparsers.add_parser("list", help="List all stored credentials")

    #Command to delete a credential
    parser_delete = subparsers.add_parsers("delete", help="Delete a credential")
    parser_delete.add_argument("name", help="Name of the credential to delete")

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        return
    
    master = getpass.getpass("Enter master password: ")

    salt = load_salt()
    key = generate_key(master, salt)
    fernet = Fernet(key)
    vault = load_vault(fernet)

    if args.command == "add":
        add.entry(args, vault, fernet)
    elif args.command == "get":
        get_entry(args, vault)
    elif args.command == "list":
        list_entries(args, vault)
    elif args.command == "delete":
        delete_entry(args, vault, fernet)
    else:
        print("Unknown command.")
    
    