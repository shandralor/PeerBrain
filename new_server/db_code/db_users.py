import hashlib
import secrets

import pymongo
import logging
from pymongo.errors import DuplicateKeyError, InvalidDocument, ConnectionFailure, PyMongoError
from dotenv import load_dotenv
from email_code.email_code import confirmation_mail
from passlib.context import CryptContext

#---DB COLLECTION INIT---#
client = pymongo.MongoClient("mongodb://localhost:27017/")
PeerbrainDB = client["peerbrain_db"]
USERS = PeerbrainDB["users"]

#---PW ENCRYPT INIT---#
pwd_context = CryptContext(schemes =["bcrypt"], deprecated="auto")

def gen_pw_hash(pw:str)->str:
    """
    Generate a hashed version of the password using the CryptContext module.

    Args:
        pw (str): The password to be hashed.

    Returns:
        str: The hashed version of the password.
    """
        
    return pwd_context.hash(pw)

#---USER COLLECTION FUNCTIONS---#
def get_users() -> dict:
    """Return a dictionary containing all users from the database.

    Returns:
        dict: A dictionary where the key is the username and the value is a dictionary containing
        the user's information.

    Raises:
        Exception: If there is an error while fetching users from the database.
    """
    try:
        all_users = {user["username"]: user for user in USERS.find()}
        return all_users
    except ConnectionFailure as e:
        logging.error("Error: Database connection failed - %s", e)
    except PyMongoError as e:
        logging.error("Error: %s", e)
    else:
        logging.info("DB Users retrieved successfully!")

def get_user_by_username(username:str) -> dict:
    """
    Query the MongoDB collection named `USERS` for a document with `_id` equal to the `username`.

    Args:
        username (str): A string representing the username to search for.

    Returns:
        Returns the document with `_id` equal to `username` if found in the `USERS` collection.
        Returns a dictionary with the message "No user with username found" if no matching document is found.

    Raises:
        ConnectionFailure: If there is a problem with the connection to the MongoDB server.
        TypeError: If the input argument is not a string.
        PyMongoError: If there is any other error while querying the database.
    """   
    try:
        user = USERS.find_one({"username": username})
        if user:
            return user
        else:
            return {"Username" : "No user with username found"}
    except ConnectionFailure as e:
        logging.error("Error: Database connection failed - %s", e)
    except TypeError as e:
        logging.error("Error: Invalid argument passed to function, type must be str", e)
    except PyMongoError as e:
        logging.error("Error: %s", e)
    else:
        logging.info(f"User {username} retrieved successfully!")

def get_user_by_email(email:str) -> dict:
    """
    Query the MongoDB collection named `USERS` for a document with `email` equal to the `email`.

    Args:
        email (str): A string representing the email to search for.

    Returns:
        Returns the document with `email` equal to `email` if found in the `USERS` collection.
        Returns a dictionary with the message "No user with email found" if no matching document is found.

    Raises:
        ConnectionFailure: If there is a problem with the connection to the MongoDB server.
        TypeError: If the input argument is not a string.
        PyMongoError: If there is any other error while querying the database.
    """   
    try:
        user = USERS.find_one({"email": email})
        if user:
            return user
        else:
            return {"Email" : "No user with email found"}
    except ConnectionFailure as e:
        logging.error("Error: Database connection failed - %s", e)
    except TypeError as e:
        logging.error("Error: Invalid argument passed to function, type must be str", e)
    except PyMongoError as e:
        logging.error("Error: %s", e)
    else:
        logging.info(f"User with email {email} retrieved successfully!")

def create_user(username:str, email:str, pw_to_hash:str):
    """
    Creates a new user document with the given username, email, and hashed password in the `USERS` collection.

    Args:
        username (str): A string representing the username of the new user.
        email (str): A string representing the email of the new user.
        pw_to_hash (str): A string representing the plain text password to be hashed for the new user.

    Returns:
        None

    Raises:
        DuplicateKeyError: If a user with the given username already exists in the `USERS` collection.
        InvalidDocument: If the new user document is invalid and cannot be inserted into the `USERS` collection.
        ConnectionFailure: If there is a problem with the connection to the MongoDB server.
        PyMongoError: If there is any other error while querying the database.
    """

    secret_token = secrets.token_hex(32)
    
    new_user = {"username" :username,
                "hashed_pw" : gen_pw_hash(pw_to_hash), 
                "email" : email,
                "friends" : [],
                "disabled" : True,
                "confirmation_token" : secret_token}

    try:
        insert_user =USERS.insert_one(new_user)
        if insert_user.acknowledged:
            confirmation_mail(email, username, secret_token)
    except DuplicateKeyError as e:
        logging.error("Error: Duplicate key - %s", e)
    except InvalidDocument as e:
        logging.error("Error: Invalid document - %s", e)
    except ConnectionFailure as e:
        logging.error("Error: Database connection failed - %s", e)
    except PyMongoError as e:
        logging.error("Error: %s", e)
    else:
        logging.info("User document inserted with id: %s", new_user["_id"])
    
def change_password(username, pw_to_hash)->str:
    """
    Update the password hash for the specified user in the MongoDB database.

    Args:
        username (str): The username of the user to update.
        pw_to_hash (str): The plaintext password to hash and set as the new password.

    Returns:
        str: A message indicating whether the update was successful or not.
             If the update was successful, the message will be in the format "User <username> password changed!".
             Otherwise, an error message will be logged and an empty string will be returned.
    Raises:
        ConnectionFailure: If there is an error connecting to the MongoDB database.
        pymongo.errors.UpdateResult: If the update operation fails.
        PyMongoError: If there is any other error during the update operation.
    """
    
    query = {'username': username}   
    hashed_pw = gen_pw_hash(pw_to_hash)
    update= {'$set': {'hashed_pw': hashed_pw}}
    
    try:
        update_result = USERS.update_one(query, update)
        if update_result.acknowledged:
            return f"User {username} password changed!"       
    except ConnectionFailure as e:
        logging.error("Error: Database connection failed - %s", e)
    except pymongo.errors.UpdateResult as e:
        if e.matched_count == 0:
            logging.error("No documents matched the query")     
    except PyMongoError as e:
        logging.error("Error: %s", e)
    else:
        logging.info(f"Password changed successfully for user {username}")
def add_otp_secret(username, key):
    """
    Add the OTP secret key to the user document in the database.

    Args:
        username (str): The username of the user to update.
        key (str): The OTP secret key to add to the user document.

    Returns:
        None
    """
    query = {'username': username}
    update = {'$set': {'otp_secret': key}}
    try:
        update_result = USERS.update_one(query, update)
        if update_result.acknowledged:
            return f"User {username} 2FA key changed!"       
    except ConnectionFailure as e:
        logging.error("Error: Database connection failed - %s", e)
    except pymongo.errors.UpdateResult as e:
        if e.matched_count == 0:
            logging.error("No documents matched the query")     
    except PyMongoError as e:
        logging.error("Error: %s", e)
    else:
        logging.info(f"2FA key changed changed successfully for user {username}")
        
def confirm_registration_token(username:str)->None:
    """
    Activate a user account by setting the 'disabled' field to False and the 'confirmation_token' field to 'verified'
    in the MongoDB collection. The user's username is used as the document ID.

    Args:
        username: A string representing the username of the user whose account needs to be activated.

    Returns:
        If the update is successful, returns a string indicating that the user account was successfully verified.
        Otherwise, returns None.

    Raises:
        ConnectionFailure: If there is an error connecting to the MongoDB database.
        pymongo.errors.UpdateResult: If the update operation fails.
        PyMongoError: If there is any other error during the update operation.
    """
    query = {'username': username}  
    update = {'$set': {
        "disabled" : False,
        "confirmation_token" : "verified"
        }
              }
    try:
        update_result = USERS.update_one(query, update)
        if update_result.acknowledged:
            return f"User {username} successfully verified!"       
    except ConnectionFailure as e:
        logging.error("Error: Database connection failed - %s", e)
    except pymongo.errors.UpdateResult as e:
        if e.matched_count == 0:
            logging.error("No documents matched the query")     
    except PyMongoError as e:
        logging.error("Error: %s", e)
    else:
        logging.info(f"User email verification successful for {username}")
