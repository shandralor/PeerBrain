"""This file will contain all the database logic for our server module. It will leverage the Deta Base NoSQL database api."""

from datetime import datetime
import math
from typing import Union
import os
import json
import logging
import requests
import secrets
from pprint import pprint #pylint: disable=unused-import
from uuid import uuid4
from deta import Deta
from dotenv import load_dotenv
from passlib.context import CryptContext
import hashlib
import datetime
from email_code import confirmation_mail, password_reset_mail

load_dotenv()

#---DB INIT---#
DETA_KEY = os.getenv("DETA_KEY")
deta = Deta(DETA_KEY)
#---#
USERS = deta.Base("users")
THOUGHTS = deta.Base("thoughts")
KEYS = deta.Base("keys_db")
TEST_USERS = deta.Base("test_users")
PW_RESET = deta.Base("pw_reset")
DM_MESSAGES = deta.Base("dm_messages")

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

def confirm_registration_token(user_key:str)->None:
    """Function that will activate a user account. Checks for validity of the token are done on the endpoint."""
    update = {"disabled" : False,
              "confirmation_token" : "verified"
                  }
    try:
        return USERS.update(update, user_key)
    except Exception as error_message:
        logging.exception(error_message)
        return None    
        
def create_user(username:str, email:str, pw_to_hash:str)->None:
    """Function to create a new user. It takes three strings and inputs these into the new_user dictionary. The function then
    attempts to put this dictionary in the database"""

    secret_token = secrets.token_hex(32)
    
    new_user = {"username" : username,
                "key" : str(uuid4()),
                "hashed_pw" : gen_pw_hash(pw_to_hash), 
                "email" : email,
                "friends" : [],
                "disabled" : True,
                "confirmation_token" : secret_token}

    try:
        confirmation_mail(email, username, secret_token)
        return USERS.put(new_user)
    except Exception as error_message:
        logging.exception(error_message)
        return None

def create_password_reset_token(username:str, email:str)->None:
    
    reset_token = secrets.token_hex(32)
    
    password_reset_object = {
        "key" : username,
        "reset_token" : reset_token
    }
    
    try:
        password_reset_mail(email, username, reset_token)
        #Password token stays valid for 5 minutes, then it gets autowiped from the database.
        return PW_RESET.put(password_reset_object, expire_in=300)
    
    except Exception as error_message:
        logging.exception(error_message)
        return None

def get_password_token(username:str)->Union[dict, None]:
    try:
        return PW_RESET.get(username)
        
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
    
def add_friend(username:str, friend_username:str):
    """Function that takes a username and the username of a friend. An update dictionary is created with that friend's username. The function 
    will then check if the friend exists, if you are not trying to add yourself or if the user in question is not already a friend. If all
    these checks are passed an attempt is made to add the friend to the friends array in the database of the User object."""
    
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

def remove_friend(username:str, friend_username:str):
    """Function that takes a username and the username of a friend. An update dictionary is created with that friend's username. The function 
    will then check if the friend exists, if you are not trying to remove yourself or if the user in question is not in your friend's list. If all
    these checks are passed an attempt is made to remove the friend from the friends array in the database of the User object."""
    
    update= {f"friends.{friend_username}": USERS.util.trim() }
    friends_list = []
    
    try:
        friends_list = USERS.fetch({"username" : username}).items[0]["friends"]
        user = get_user_by_username(username)
        user_key = user["key"]
        if not friend_username in friends_list:
            return {"Username" : "Not Found"}
        elif username == friend_username:
            return {"Username" : "You can't remove yourself as your friend!"}
        else:
            new_friends_list = [friend for friend in friends_list if friend != friend_username]
            update= {"friends": new_friends_list }
            return USERS.update(update, user_key) 
    except Exception as error_message:
        logging.exception(error_message)
        return None   

#---THOUGHTS FUNCTIONS---#

def calculate_rating_increase(rating:float)->float:
    """Helper function that takes the rating float from a Thoughts object and performs a logarithmic calculation on it. The result is 
    then returned."""
    increase = 1
    base = 2
    if rating <=1:
        rating=1.1
    
    return rating + increase * math.log(rating, base)
    
def update_thought_rating(key:str)->Union[dict, str, None]:
    """Function to increase a thoughts rating using the increase function we defined earlier."""
    thought = THOUGHTS.get(key)
    rating = thought["rating"]
    new_rating = calculate_rating_increase(rating)
    
    update = {"rating" : new_rating}
    try:
        THOUGHTS.update(update, key)
        print(new_rating)
    except Exception as error_message:
        logging.exception(error_message)
        return None

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
                result_list_thoughts.append({"title":thought["title"], "content" : thought["content"], "rating" : thought["rating"], "key" : thought["key"]})
                    
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


#---DIRECT MESSAGE FUNCTIONS---#

#prepare the usernames of the conversation participants for hash generation
def concatenate_usernames(username1:str, username2:str)->str:
    """Function that will trim usernames if they are too long and then concatenate them
    alphabetically with an underscore between them. Returns the concatenated string."""
    # sort usernames alphabetically to ensure consistent ordering
    username1 = username1[:5]
    username2 = username2[:5]
    sorted_usernames = sorted([username1, username2])
    # join sorted usernames with an underscore
    concatenated_usernames = '_'.join(sorted_usernames)
    return concatenated_usernames

#generate a hash key to identify the current conversation. This key will always be the same as long as the
#usernames are provided to the function
def generate_database_key_hash(username1:str, username2:str)->str:
    """Function that will take the concatenated string of usernames and generate a reproducable hash
    to serve as a database key."""
    # concatenate usernames alphabetically
    concatenated_usernames = concatenate_usernames(username1, username2)
    # hash concatenated usernames using SHA-256 hash function
    hash_object =hashlib.sha256(concatenated_usernames.encode())
    key_hash_hex = hash_object.hexdigest()
    return key_hash_hex

def get_message_status(generated_database_key_hash:str):
    """Function that will return the highest order number for a conversation. If no conversation exist it will return
    None."""
    status = DM_MESSAGES.get(generated_database_key_hash)
    if status:
        return max(map(int, status["conversation"].keys()))
    return 

def push_message_to_database(speaker:str, receiver:str, message:str):
    """Function that will enter a new conversation in the database in none exists. If it does exist it will update the conversation
    with the newest message."""
    generated_database_key_hash = generate_database_key_hash(speaker, receiver)
    
    order_number = get_message_status(generated_database_key_hash)
    if order_number:
        order_number+=1
        update = {
            f"conversation.{order_number}" : {
                "speaker" : speaker,
                "text" : message,
                "date_time" : str(datetime.datetime.utcnow())
            }
        }
        try:
            DM_MESSAGES.update(update, generated_database_key_hash)
        except Exception as error_message:
            logging.exception(error_message)
            return 
    else:
        order_number = 1
    
        update = {
            "key": generated_database_key_hash,
            "conversation": {
                order_number: {
                    "speaker": speaker,
                    "text": message,
                    "date_time": str(datetime.datetime.utcnow())
                }
            }
        }
        try:
            DM_MESSAGES.put(update)
        except Exception as error_message:
            logging.exception(error_message)
            return

def get_conversation(speaker:str, receiver:str):
    conversation_key = generate_database_key_hash(speaker, receiver)
    conversation_object = DM_MESSAGES.get(conversation_key)
    
    if conversation_object:    
        conversation = conversation_object["conversation"]
        conversation_json_list = []
    
        for key in sorted(conversation.keys()):
            speaker = conversation[key]["speaker"]
            text = conversation[key]['text']
            conversation_json_list.append({"speaker" : speaker, "text" : text})
            
        return json.dumps(conversation_json_list)
    return {"Error" : "No conversation found for those users!"}
