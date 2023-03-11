"""This file will contain all the database logic for our server module. It will leverage the Deta Base NoSQL database api."""

from datetime import datetime
import math
from typing import Union
import os
import json
import logging
import requests
from pprint import pprint #pylint: disable=unused-import
from uuid import uuid4
from deta import Deta
from dotenv import load_dotenv
from passlib.context import CryptContext

load_dotenv()

#---DB INIT---#
DETA_KEY = os.getenv("DETA_KEY")
deta = Deta(DETA_KEY)
#---#
USERS = deta.Base("users")
THOUGHTS = deta.Base("thoughts")
KEYS = deta.Base("keys_db")


#---PW ENCRYPT INIT---#
pwd_context = CryptContext(schemes =["bcrypt"], deprecated="auto")
#---#
def gen_pw_hash(pw:str)->str:
    """
    Generate a hashed version of the password using the CryptContext module.

    Args:
        pw (str): The password to be hashed.

    Returns:
        str: The hashed version of the password.
    """
        
    return pwd_context.hash(pw)

#---USER FUNCTIONS---#
def get_users() -> dict:
    """Return a dictionary containing all users from the database.

    Returns:
        dict: A dictionary where the key is the username and the value is a dictionary containing
        the user's information.

    Raises:
        Exception: If there is an error while fetching users from the database.
    """
    try:
        return {user["username"]: user for user in USERS.fetch().items}
    except Exception as e:
        # Log the error or handle it appropriately
        print(f"Error fetching users: {e}")
        return {}

def get_user_by_username(username:str)->Union[dict, None]:
    """Return a user object if it exists in the database, otherwise return a JSON object with a message.

    Args:
        username (str): The username of the user to retrieve.

    Returns:
        Union[dict, None]: A dictionary containing user information if the user is found in the database.
        If the user is not found, a dictionary containing a message indicating that no user exists for that username.
        If an exception occurs during execution, None is returned.
    """
    
    try:
        if (USERS.fetch({"username" : username}).items) == []:
            return {"Username" : "No user with username found"}
        else:
            return USERS.fetch({"username" : username}).items[0]
    except Exception as error_message:
        logging.exception(error_message)
        return None

def get_user_by_email(email:str)->Union[dict, None]:
    """Function that returns a User object if it is in the database. If not it returns a JSON object with the 
    message no user exists for that email address"""
    
    try:
        if (USERS.fetch({"email" : email}).items) == []:
            return {"Email" : "No user with email found"}
        else:
            return USERS.fetch({"email" : email}).items[0]
    except Exception as error_message:
        logging.exception(error_message)
        return None

def change_password(username, pw_to_hash):
    """Function that takes a username and a password in plaintext. It will then hash that password>
    After that it creates a dictionary and tries to match the username to users in the database. If 
    successful it overwrites the previous password hash. If not it returns a JSON message stating no 
    user could be found for the username provided."""
    
    hashed_pw = gen_pw_hash(pw_to_hash)
    update= {"hashed_pw": hashed_pw }
    
    try:
        user = get_user_by_username(username)
        user_key = user["key"]
        if not username in get_users():
            return {"Username" : "Not Found"}
        else:
            
            return USERS.update(update, user_key), f"User {username} password changed!"
    except Exception as error_message:
        logging.exception(error_message)
        return None       
    
def create_user(username:str, email:str, pw_to_hash:str)->None:
    """Function to create a new user. It takes three strings and inputs these into the new_user dictionary. The function then
    attempts to put this dictionary in the database"""

    new_user = {"username" : username,
                "key" : str(uuid4()),
                "hashed_pw" : gen_pw_hash(pw_to_hash), 
                "email" : email,
                "friends" : [],
                "disabled" : False}
    try:
        return USERS.put(new_user)
    except Exception as error_message:
        logging.exception(error_message)
        return None
    
#---FRIENDS FUNCTIONS---#    
def get_friends_by_username(username:str)->Union[dict, None]:
    """Function that will get a list of all usernames in the friends array of the user object. It will then collect all the friends
    user profile info for each friend, add it to a dictionary and then return that dictionary."""
    
    friends_list =[]
    
    try:
        friends_list = USERS.fetch({"username" : username}).items[0]["friends"]
        friends_dict = {}
        for friend in friends_list:
            user = get_user_by_username(friend)
            friends_dict[user['username']] = {"email":user['email']}
        return friends_dict    
    except Exception as error_message:
        logging.exception(error_message)
        return None
    
def add_friend(username, friend_username):
    """Function that takes a username and the username of a friend. An update dictionary is created with that friend's username. The function 
    will then check if the friend exists, if you are not trying to add yourself or if the user in question is not already a friend. If all
    these checks are passed and attempt is made to add the friend to the friends array in the database of the User object."""
    
    update= {"friends": USERS.util.append(friend_username) }
    
    try:
        user = get_user_by_username(username)
        user_key = user["key"]
        if not friend_username in get_users():
            return {"Username" : "Not Found"}
        elif username == friend_username:
            return{"Username" : "You can't add yourself as a friend!"}
        elif friend_username in user["friends"]:
            return {"Username" : "Already a friend!"}
        else:
            return USERS.update(update, user_key), f"User {friend_username} added as a friend successfully!"
    except Exception as error_message:
        logging.exception(error_message)
        return None
    

#---THOUGHTS FUNCTIONS---#
def update_rating(rating:float)->float:
    """Helper function that takes the rating float from a Thoughts object and performs a logarithmic calculation on it. The result is 
    then returned."""
    
    rating += math.log(rating+1)
    return rating

def get_thought(query_str:str)->Union[dict, str, None]:
    """Function to find a Thought by title. Might need refinement when implementing the encryption aspect."""
    try:
        thought_list=THOUGHTS.fetch().items
        for thought in thought_list:
            if query_str.lower() in thought["title"].lower():
                return thought
            else:
                return f"No thought found for the search term {query_str}"
    except Exception as error_message:
        logging.exception(error_message)
        return None

def get_thoughts(username:str)->Union[dict, None]:
    """Function to find all thoughts that have the given username in its list. It will return a dictionary of 
    all the Thought objects that have the usernames username provided."""
    try:
        result_list_thoughts = []
        results = THOUGHTS.fetch().items
        for thought in results:
            if username == thought["username"]:
                result_list_thoughts.append({"title":thought["title"], "content" : thought["content"], "rating" : thought["rating"]})
                    
        return json.dumps(result_list_thoughts)
        
    except Exception as error_message:
        logging.exception(error_message)
        return None

def create_thought(username:str, title:str, content:str)->None:
    """Basic function to create a Thought. Will need refinement to handle encrypted data for the content field and probably an additional array
    to store all the versions of the encrypted symmetric key."""
    new_thought = {"username" : username,
                   "key" : str(uuid4()), 
                   "title" : title, 
                   "content" : content,
                   "rating" : 0.0,
                   "creation_date": str(datetime.utcnow())
                   }
    
    try:
        return THOUGHTS.put(new_thought)
    except Exception as error_message:
        logging.exception(error_message)
        return None


#---PUBLIC KEY FUNCTIONS---#

def send_keys_to_remote_server(public_key:str, symmetric_key:str, username:str, hashed_password:str)->Union[bool, None]:
    """Helper function to allow the endpoint to upload a provided public key string to the database. It will also use the get_public_key
    function to verify that the key in the database matches the original. Improvement needed on removing a public key that does not match the check
    from the database again."""
    
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
        print(type(data["Friend Symmetric Key"]))
        return data["Friend Symmetric Key"]
    else:
        print(f"Request to remote server failed with error code {response.status_code}")


