import logging
import os
from dotenv import load_dotenv
import requests
from db_users import get_users, get_user_by_username


def send_keys_to_remote_server(public_key:str, symmetric_key:str, username:str, hashed_password:str):
    """
    Helper function to upload a provided public key string to the database for a user specified by username and hashed password.
    It will also verify that the key in the database matches the original using the get_public_key function.
    
    Args:
    - public_key (str): The public key to be uploaded to the database
    - symmetric_key (str): The symmetric key to be associated with the public key in the database
    - username (str): The username of the user whose public key is being uploaded
    - hashed_password (str): The hashed password of the user whose public key is being uploaded
    
    Returns:
    - None
    Raises:
    None: This function does not raise any exceptions.
    """
    
    user_key_store = {
        "username" : username,
        "user_password_hash" : hashed_password,
        "key_store" : {
            "public_key" : public_key,
            "symmetric_key" : symmetric_key
        }
    }
    
    url = os.getenv("SYM_KEY_API_URL")
    url_suffix = "api/v1/user_key"
    
    headers = {
    "Content-Type": "application/json",
    "api-key": os.getenv("SYM_KEY_API_KEY"),
    "x-api-key": os.getenv("SYM_KEY_X_API_KEY")
    }
    
    response = requests.post(f"{url}{url_suffix}", headers=headers, json=user_key_store)
    
    if response.status_code == 200:
        print("Keystore sent successfully to remote server.")
    else:
        print(f"Request to remote server failed with error code {response.status_code}")

def get_encrypted_sym_key(username: str, user_password, friend_username:str):
    """Retrieves the encrypted symmetric key for a friend from a remote server using the user's login credentials.

    Args:
    username (str): The username of the user making the request.
    user_password (str): The password of the user making the request.
    friend_username (str): The username of the friend for whom the symmetric key is being requested.

    Returns:
    str: The encrypted symmetric key for the friend.

    Raises:
    None: This function does not raise any exceptions.
    """
    encrypted_sym_request = {
        "username" : username,
        "password" : user_password,
        "friend_username" : friend_username
    }
    
    url = os.getenv("SYM_KEY_API_URL")
    url_suffix = "api/v1/user_keys"
    
    headers = {
    "Content-Type": "application/json",
    "api-key": os.getenv("SYM_KEY_API_KEY"),
    "x-api-key": os.getenv("SYM_KEY_X_API_KEY")
    }
    
    response = requests.post(f"{url}{url_suffix}", headers=headers, json=encrypted_sym_request)
    data = response.json()
    if response.status_code == 200:
        print("Key received successfully from remote server.")
        return data["Friend Symmetric Key"]
    else:
        print(f"Request to remote server failed with error code {response.status_code}")