import logging

import pymongo
from dotenv import load_dotenv
from email_code.email_code import confirmation_mail
from db_users import get_users, get_user_by_username
from pymongo.errors import (ConnectionFailure, DuplicateKeyError,
                            InvalidDocument, PyMongoError)

#---DB COLLECTION INIT---#
client = pymongo.MongoClient("mongodb://localhost:27017/")
PeerbrainDB = client["peerbrain_db"]
USERS = PeerbrainDB["users"]

#---FRIENDS FUNCTIONS---# 
   
def get_friends_by_username(username:str):
    """
    Retrieve a dictionary containing the user profile info for all friends associated with the given username.

    Args:
        username (str): The username for which to retrieve friend information.

    Returns:
        dict: A dictionary containing the user profile info for all friends associated with the given username.
              The dictionary keys are the friends' usernames, and the values are dictionaries containing the
              friends' email addresses.
    Raises:
        KeyError: If the provided key for the friend was invalid.
        PyMongoError: If there is any other error while querying the database.
    """
          
    try:
        friends_list = USERS.find_one({"username" : username})["friends"]
        friends_dict = {}
        for friend in friends_list:
            user = get_user_by_username(friend)
            friends_dict[user['username']] = {"email":user['email']}
        return friends_dict    
    except KeyError as e:
        logging.exception("KeyError occurred while accessing friend's info for user: {}".format(friend))
    except PyMongoError as e:
        logging.error("Error: %s", e)
    else:
        logging.info(f"Friends list retrieved successfully!")
        
def add_friend(username:str, friend_username:str):
    """
    Function that adds a friend to a user's friend list in the database.

    Args:
        username: A string representing the username of the user who wants to add a friend.
        friend_username: A string representing the username of the friend to be added.

    Returns:
        A dictionary containing a message about the success or failure of the friend addition.

    Raises:
        PyMongoError: An error occurred while trying to update the database.
    """
    
    filter = {"username": username}
    update = {"$push": {"friends": friend_username}}
    
    try:
        if not friend_username in get_users():
            return {"Friend username" : "Not Found"}
        elif username == friend_username:
            return{"Friend username" : "You can't add yourself as a friend!"}
        elif friend_username in get_user_by_username(username)["friends"]:
            return {"Friend username" : "Already a friend!"}
        USERS.update_one(filter, update)
    except PyMongoError as e:
        logging.error("Error: %s", e)
    else:
        logging.info(f"User {username} successfully added as a friend!")
    
def remove_friend(username:str, friend_username:str):
    """
    Removes a friend from the friend list of a given user.
    
    Args:
        username (str): The username of the user whose friend list the friend is to be removed from.
        friend_username (str): The username of the friend to be removed.
        
    Returns:
        dict: A dictionary containing a message indicating the result of the removal process.
        
    Raises:
        PyMongoError: If there is an error while updating the database.
    """
    
    filter = {"username": username}
    update = {"$pull": {"friends": friend_username}}
    
    try:
        if not friend_username in get_users():
            return {"Friend username" : "Not Found"}
        elif username == friend_username:
            return{"Friend username" : "You can't delete yourself as a friend!"}
        elif friend_username not in get_user_by_username(username)["friends"]:
            return {"Friend username" : "Not in your friend list!"}
        USERS.update_one(filter, update)
    except PyMongoError as e:
        logging.error("Error: %s", e)
    else:
        logging.info(f"User {username} successfully added as a friend!")