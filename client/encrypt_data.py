import os
from dotenv import load_dotenv
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.fernet import Fernet
from typing import Union
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import logging
from passlib.context import CryptContext
import requests


load_dotenv()

#---PW ENCRYPT INIT---#
pwd_context = CryptContext(schemes =["bcrypt"], deprecated="auto")
#---#
def gen_pw_hash(pw:str)->str:
    """Function that will use the CryptContext module to generate and return a hashed version of our password"""
    
    return pwd_context.hash(pw)

def verify_password(plain_text_pw:str, hash_pw:str)->bool:
    """Returns True if password hash matches the plain text password. Returns False otherwise."""
    return pwd_context.verify(plain_text_pw, hash_pw)

# Generate a new RSA key pair for a client
def generate_keypair()->tuple:
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    private_key = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_key = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    return public_key, private_key

def load_sym_key()->bytes:
     # Load the key from a file
    key_path = os.path.join(os.path.dirname(__file__), 'keys', 'message.key')
    with open(key_path, 'rb') as key_file:
        key = key_file.read()
        return key

#Detect if a private key is available on your system        
def detect_private_key()->bool:
    if os.path.exists(os.path.join(os.path.dirname(__file__), 'keys', 'private_key.pem')):
        print("Found local private key.")
        return True
    else:
        print("No local private key found.")
        return False
    
def detect_public_key()->bool:
    if os.path.exists(os.path.join(os.path.dirname(__file__), 'keys', 'public_key.pem')):
        print("Found local public key.")
        return True
    else:
        print("No local public key found.")
        return False
    
#Load your private key after checking if one is available on your system    
def load_private_key():
    if detect_private_key:
        key_path = os.path.join(os.path.dirname(__file__), 'keys', 'private_key.pem')
        with open(key_path, 'rb') as f:
            key_data = f.read()
            key = serialization.load_pem_private_key(
            key_data,
            password=None)
            private_key = key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
                )
            return private_key

def load_public_key():
    key_path = os.path.join(os.path.dirname(__file__), 'keys', 'public_key.pem')
    with open(key_path, 'rb') as f:
        key_data = f.read()
        key = serialization.load_pem_public_key(
            key_data
        )
        public_key = key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return public_key
    
#Save private key to local storage
def save_private_key(private_key:bytes)->None:
    key_path = os.path.join(os.path.dirname(__file__), 'keys', 'private_key.pem')
    with open(key_path, 'wb') as f:
        f.write(private_key)
        
    reloaded_key = load_private_key()
    if private_key == reloaded_key:
        print("Private key saved successfully")
    else:
        print("Private key not saved successfully, please try again!")

def save_public_key(public_key: bytes) -> None:
    key_path = os.path.join(os.path.dirname(__file__), 'keys', 'public_key.pem')
    with open(key_path, 'wb') as f:
        f.write(public_key)

    reloaded_key = load_public_key()
    if public_key == reloaded_key:
        print("Public key saved successfully")
    else:
        print("Public key not saved successfully, please try again!")
        
def encrypt_message_symmetrical(message:str)-> bytes:
    try:
        symmetric_key = load_sym_key()
        # Create a Fernet object using the key
        fernet = Fernet(symmetric_key)
        # Encrypt the text string
        encrypted_text = fernet.encrypt(message.encode())
        return symmetric_key, encrypted_text
    except Exception as error_message:
        logging.exception(error_message)

def decrypt_message(encrypted_message, encryption_sim_key):
    private_key = serialization.load_pem_private_key(
    load_private_key(), password=None)

    # Decrypt the encrypted key using the private key
    decrypted_key = private_key.decrypt(
        encryption_sim_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None))
    # Create a Fernet object with the symmetric key
    fernet = Fernet(decrypted_key)

    # Decrypt the encrypted message
    decrypted_message = fernet.decrypt(encrypted_message)

    # Decode the decrypted message bytes to string
    decrypted_message = decrypted_message.decode()

    # Print the decrypted message
    return decrypted_message

def generate_sym_key()->None:
    # Generate a symmetric key
    key = Fernet.generate_key()

    # Save the key to a file
    key_path = os.path.join(os.path.dirname(__file__), 'keys', 'message.key')
    with open(key_path, 'wb') as key_file:
        key_file.write(key)

    if load_sym_key() == key:
        print("Symmetric key saved successfully")
    else:
        print("Symmetric key not saved successfully, please try again!")
    return key

def detect_sym_key()->bool:
    if os.path.exists(os.path.join(os.path.dirname(__file__), 'keys', 'message.key')):
        print("Found local sym key.")
        return True
    else:
        print("No local private sym found.")
        return False

