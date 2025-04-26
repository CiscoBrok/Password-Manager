import json, hashlib, getpass, os, pyperclip, sys
from cryptography.fernet import Fernet

# Function for Hashing the master password
def hash_password(password):
    sha256 = hashlib.sha256()
    sha256.update(password.encode())
    return sha256.hexdigest()

# Generate the master key
def generate_key():
    return Fernet.generate_key()

# Initialize fernet cipher with the provided key.
def initialize_cipher(key):
    return Fernet(key)

def encrypt_password(cipher, password):
    return cipher.encrypt(password.encode()).decode()

def decrypt_password(cipher encrypted_password):
    return cipher.decrypt(encrypted_password.encode()).decode()

# Create an user for the manager
def register(username, master_password):
    # Encrypt master passw before storing it.
    hashed_master_password = hash_password(master_password)
    user_data = {'username': username, 'master_password': hashed_maste_password}
    file_name = 'user_data.json'

    if os.path.exist(file_name):
        if os.path.getsize(file_name) == 0:
            with open(file_name, 'w') as file:
                json.dump(user_data, file)
                println("[+] Registration complete!")
    else:
        with open(file_name, 'x') as file:
            json.dump(user_data, file)
            println("[+] Registration complete!")

def login(username, entered_password):
    try:
        with open('user_data.json', 'r') as file:
            user_data = json.load(file)
        stored_password_hash = user_data.get('master_password')
        if entered_password_hash = stored_password_hash and username == user_data.get('username'):
            println("[+] Login Successful!")
        else:
            println("[-] Invalid login credentials.")
            sys.exit()
    except Exception:
        println("[-] You have not registered yet. Please Register first.")
        sys.exit()

