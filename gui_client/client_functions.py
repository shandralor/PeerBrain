import os
import json
import requests
from typing import List, Tuple, Union

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

import getpass
#---VARIABLES---#
login_headers = {"Content-Type": "application/x-www-form-urlencoded"}

def log_in_to_server(username:str, password:str, server_url):

    #--> Check if the token.json file exists in the current directory
    if os.path.exists("token.json"):

        #--> Define the headers with the Authorization token
        headers = {"Authorization": f"Bearer {get_token()}"}

        #--> Make a GET request to the protected endpoint with the headers
        response = requests.get(f"{server_url}api/v1/token-test", headers=headers,timeout=10)

        #-->Token is present but no longer valid
        if response.status_code == 401:
            # Define the payload with the username and password
            payload = {"username": username.lower(), "password": password}
            login_response = requests.post(server_url, data=payload, timeout=10)

            # Extract the JWT token from the response
            jwt_token = login_response.json()["access_token"]

            create_token(jwt_token)
            print()
            print("Logged in successfully!")
            print()

        print()
        print("Logged in with valid token")
        print()

    else:
        #-->No token found, request a new one
        
        # Define the payload with the username and password
        payload = {"username": username.lower(), "password": password}
        # Make a POST request to the login endpoint with the payload
        login_response = requests.post(server_url, data=payload, headers=login_headers, timeout=10)

        # Extract the JWT token from the login response
        jwt_token = login_response.json()["access_token"]

        # Set the JWT token in token.json file
        create_token(jwt_token)

        print()
        print("Logged in successfully!")
        print()
        
def get_token()->str:
    """Function to get the json token from a local json file called token.json"""
    with open("token.json", "r", encoding='utf-8') as file:
        data = json.load(file)
        jwt_token = data["token"]
        return jwt_token

def create_token(jwt_token:str)->None:
    """Function to write the json token to a local json file called token.json"""
    with open("token.json", "w", encoding='utf-8') as file:
        data = {"token": jwt_token}
        json.dump(data, file)

def get_account_info(server_url:str)->tuple:
    """Function that returns account details for the endpoint specified in the 
    account_url_suffix variable"""
    account_url_suffix = "api/v1/me"
    headers = {"Authorization": f"Bearer {get_token()}"}
    response = requests.get(f"{server_url}{account_url_suffix}", headers=headers, timeout=10)
    data = response.json()

    try:
        return data['username'], data['email']
    except KeyError:
        print(data["detail"])
        print()

def get_sym_key(server_url:str, password:str, friend_username:str)->str:
    """Function that uploads the encrypted symmetric key from the db"""

    account_url_suffix = "api/v1/user_key_request"
    headers = {"Authorization": f"Bearer {get_token()}"}
    
    payload={
        "user_password" : password,
        "friend_username" : friend_username      
    }
    
    response = requests.post(f"{server_url}{account_url_suffix}", json=payload,  headers=headers, timeout=10)    
    data = response.json()
    return data

def post_thought(server_url:str, username:str, title:str, encrypted_message:bytes):
    """Function that uploads the Thought and its list of usernames and encrypted keys to the endpoint specified in the 
    account_url_suffix variable"""

    account_url_suffix = "api/v1/thoughts"
    headers = {"Authorization": f"Bearer {get_token()}"}
    
    payload={
        "username" : username.lower(),
        "title" : title,
        "content" : encrypted_message.decode("utf-8")        
    }
    
    response = requests.post(f"{server_url}{account_url_suffix}", json = payload,  headers=headers, timeout=10)

def register_user(server_url:str, username:str, user_email:str, user_password:str, friends:List[str]=[]):
    """function to return a list of all user friends."""
   
    account_url_suffix = "api/v1/users"

    payload = {
    'username': username.lower(),
    'email': user_email,
    'user_password': user_password,
    "friends" : friends,
    "disabled" : False
    }
    
    response = requests.post(f"{server_url}{account_url_suffix}", json=payload, timeout=10)

    data = response.json()
    return data.items()

def add_user_friends(server_url:str, friend_username:str):
    """function to return a list of all user friends."""
    account_url_suffix = "api/v1/friends/"

    headers = {"Authorization": f"Bearer {get_token()}"}
    
    response = requests.post(f"{server_url}{account_url_suffix}{friend_username}", headers=headers, timeout=10)

    data = response.json()
    
    return data

def reset_password(server_url:str, username:str):
    """Function to start the password reset process."""
    account_url_suffix = "get_password_reset_token"

    data = {
        "username" : username
    }
    
    response = requests.post(f"{server_url}{account_url_suffix}", json=data,  timeout=10)

    if response.status_code ==200:
        print("Response content:", response.content)    
    else:
        print("Something went wrong with the password reset request!")

def post_conversation_message(server_url:str, friend_username:str, message:str):
    """Function to start the password reset process."""
    account_url_suffix = "api/v1/dm-conversation"

    headers = {"Authorization": f"Bearer {get_token()}"}
    
    data = {
        "friend_username" : friend_username,
        "message" : message
    }
    
    response = requests.post(f"{server_url}{account_url_suffix}", json=data,  headers=headers, timeout=10)

    if response.status_code ==200:
        print("Message set succesfully!")    
    else:
        print("Something went wrong with sending your message!")

def get_user_friends(server_url:str)->tuple:
    """function to return a list of all user friends."""
    account_url_suffix = "api/v1/friends"

    headers = {"Authorization": f"Bearer {get_token()}"}

    response = requests.get(f"{server_url}{account_url_suffix}", headers=headers, timeout=10)

    data = response.json()

    usernames = []
    for key in data.items():
        usernames.append(key)
        
    return tuple(usernames)

def update_rating_for_thought(server_url:str, key:str):
    """function to update a thoughts rating when it is read"""
    account_url_suffix = "api/v1/update-thought-rating"

    headers = {"Authorization": f"Bearer {get_token()}"}

    params = {"key": key}

    response = requests.get(
        f"{server_url}{account_url_suffix}",
        headers=headers,
        params=params["key"],
        timeout=10
    )

    data = response.json()

    if response.status_code != 200:
        # Print an error message
        print(data)
        print(f"Error: {response.status_code}" )

def get_user_conversation(server_url:str, friend_username:str)->List:
    """function to get a conversation if it exists"""
    account_url_suffix = "api/v1/dm-conversation"

    headers = {"Authorization": f"Bearer {get_token()}"}

    params = {"friend_username" : friend_username}
    
    response = requests.get(f"{server_url}{account_url_suffix}", headers=headers, params=params, timeout=10)

    data = response.json()
    print("\n\n")
    print('--------')
    if type(data) == dict:
        print(data)
    else:
        #prints the conversation
        for message in json.loads(data):
            print(f"{message['speaker']} :{ message['text']}\n")
    print('--------')
    if not response.status_code == 200:
        # Print an error message
        print(data)
        print(f"Error: {response.status_code}" )

def remove_user_friends(server_url:str, friend_username:str)->None:
    """function to return a list of all user friends."""
    account_url_suffix = "api/v1/remove-friend"

    headers = {"Authorization": f"Bearer {get_token()}"}

    params = {"friend_username" : friend_username}
    
    response = requests.get(f"{server_url}{account_url_suffix}", headers=headers, params = params, timeout=10)

    data = response.json()

    if response.status_code == 200:
        # Print the response content
        print(f"Succes : You successfully removed {friend_username} from your friends list!")
    else:
        # Print an error message
        print(data)
        print(f"Error: {response.status_code}" )
        
def get_all_users(server_url:str)->tuple:
    """Development function to get all users in the database. Will be deprecated on app release."""
    account_url_suffix = "api/v1/users"

    headers = {"Authorization": f"Bearer {get_token()}"}

    response = requests.get(f"{server_url}{account_url_suffix}", headers=headers, timeout=10)
    
        
    data = response.json()

    all_users = data.items()
    return all_users

def get_thoughts_for_user(server_url:str, username:str)->Tuple[str, str]:
    """Function that returns all thoughts that have the username in the reader's list for the endpoint specified in the 
    account_url_suffix variable"""
    account_url_suffix = "api/v1/thoughts"
    headers = {"Authorization": f"Bearer {get_token()}"}
    response = requests.get(f"{server_url}{account_url_suffix}/{username}", headers=headers, timeout=10)
    data = response.json()
    return json.loads(data)

def wrap_encrypt_sym_key(sym_key:bytes, server_url:str, friend_username: Union[str, None] = None)->Union[str, bytes]:
    """Function to prepare the public key to encrypt the symmetric key, and then encrypt it. The optional friend_username
    argument is used to check if it is the users own key that needs encrypting or someone else's."""
    if friend_username:
        public_key = serialization.load_pem_public_key(get_public_key_friend(server_url, friend_username).encode('utf-8'))#==To change to use the endpoint, drop the username
        # Encrypt the symmetric key with the client's public key
        encrypted_sim_key = public_key.encrypt(sym_key,padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            ))
        return encrypted_sim_key
    else:    
        public_key = serialization.load_pem_public_key(get_public_key(server_url).encode('utf-8'))#==To change to use the endpoint, drop the username
        # Encrypt the symmetric key with the client's public key
        encrypted_sim_key = public_key.encrypt(sym_key,padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            ))
        return encrypted_sim_key
    
def upload_keystore(server_url:str, public_key:bytes, symmetric_key:bytes):
    """Function that uploads the generated public key to the endpoint specified in the 
    account_url_suffix variable"""

    # try:
    account_url_suffix = "api/v1/post_key_store"
    headers = {"Authorization": f"Bearer {get_token()}"}
    
    print(type(public_key))
    payload={
        "pub_key" : public_key.decode("utf-8"),
        "symmetric_key": symmetric_key.decode("utf-8")
    }
    
    response = requests.post(f"{server_url}{account_url_suffix}", json = payload,  headers=headers, timeout=10)
    
    data = response.json()
    
    return data

def check_token(server_url:str)->bool:
    """Function that checks if a token exists and is valid"""

    # Check if the token.json file exists in the current directory
    if os.path.exists("token.json"):
        # Define the headers with the Authorization token
        headers = {"Authorization": f"Bearer {get_token()}"}

        # Make a GET request to the protected endpoint with the headers
        response = requests.get(f"{server_url}api/v1/token-test", headers=headers,timeout=10)

        # Token is present and valid
        if response.status_code == 200:
            print()
            print("Logged in with valid token")
            print()
            return True
    return False

def login(server_url:str, username:str, password:str)->None:
    """Function that logs the user in"""

    # Define the payload with the username and password
    payload = {"username": username.lower(), "password": password}

    # Make a POST request to the login endpoint with the payload
    login_response = requests.post(server_url, data=payload, headers=login_headers, timeout=10)

        
    #Will check if the detail key is present in the json response. If so this means the user is inactive
    if "detail" in login_response.json():
        print(login_response.json()["detail"])
        return False
        
    
    # Extract the JWT token from the login response
    jwt_token = login_response.json()["access_token"]

    # Set the JWT token in token.json file
    create_token(jwt_token)

    print()
    print("Logged in successfully!")
    print()
        
    return True
    
def login_with_token(server_url:str)->None:
    """Function that tries to log in with a token first. If the token is not valid or
    does not exist, it logs in with the provided username and password"""

    # if check_token(server_url):
    #     return True
    username = input("Please enter your username: ")
    password = getpass.getpass(prompt = "Please enter your password: ")
    
    # Token is not valid or does not exist, log in with username and password
    login(server_url, username.lower(), password)

    if login(server_url, username, password):
        return True
    else:
        return False

def log_out():
    file_path = "token.json"  
    if os.path.exists(file_path):
        os.remove(file_path)
        print("Logged out successfully!")
    else:
        print("You are not logged in!")   
        
