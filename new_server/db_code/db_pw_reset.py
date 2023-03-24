import logging
import secrets
from datetime import datetime, timedelta

import pymongo
from dotenv import load_dotenv
from email_code.email_code import password_reset_mail
from pymongo.errors import (ConnectionFailure, DuplicateKeyError,
                            InvalidDocument, PyMongoError)

#---DB COLLECTION INIT---#
client = pymongo.MongoClient("mongodb://localhost:27017/")
PeerbrainDB = client["peerbrain_db"]
PW_RESET = PeerbrainDB["pw_reset"]


#---PW_RESET COLLECTION FUNCTIONS---#
def create_password_reset_token(username:str, email:str):
    """
    Creates a password reset token for the given user and inserts it into the "PW_RESET" collection in the database.
    
    Parameters:
    - username (str): The username of the user who requested the password reset.
    - email (str): The email address of the user who requested the password reset.
    
    Returns:
    None
    
    Raises:
    - DuplicateKeyError: If a document with the same "_id" value already exists in the "PW_RESET" collection.
    - InvalidDocument: If the password reset object is invalid or cannot be serialized.
    - ConnectionFailure: If there is an error connecting to the database.
    - PyMongoError: If there is an error inserting the document into the "PW_RESET" collection.
    """
    PW_RESET.create_index("created_at", expireAfterSeconds=300)
    reset_token = secrets.token_hex(32)
    created_at = datetime.utcnow()
        
    password_reset_object = {
        "_id" : username,
        "reset_token" : reset_token,
        "created_at" : created_at}
    
    try:
        pw_reset_token_document=PW_RESET.replace_one({'_id': username}, password_reset_object, upsert=True)
        if pw_reset_token_document.acknowledged:
            password_reset_mail(email, username, reset_token)
    except DuplicateKeyError as e:
        logging.error("Error: Duplicate key - %s", e)
    except InvalidDocument as e:
        logging.error("Error: Invalid document - %s", e)
    except ConnectionFailure as e:
        logging.error("Error: Database connection failed - %s", e)
    except PyMongoError as e:
        logging.error("Error: %s", e)
    else:
        logging.info(f"Password reset token created successfully for user {username}")
        
def get_password_token(username:str)->dict:
    """
    Retrieves the password reset token for the given username from the "PW_RESET" collection in the database.
    
    Parameters:
    - username (str): The username of the user for whom the password reset token is being retrieved.
    
    Returns:
    - dict: A dictionary containing the password reset token if it exists in the "PW_RESET" collection, otherwise None.
    
    Raises:
    - ConnectionFailure: If there is an error connecting to the database.
    - TypeError: If an argument with an incorrect type is passed to the function.
    - PyMongoError: If there is an error retrieving the password reset token from the "PW_RESET" collection.
    """

    try:
        reset_token = PW_RESET.find_one(username)
        if reset_token:
            return reset_token
        
    except ConnectionFailure as e:
        logging.error("Error: Database connection failed - %s", e)
    except TypeError as e:
        logging.error("Error: Invalid argument passed to function, type must be str", e)
    except PyMongoError as e:
        logging.error("Error: %s", e)
    else:
        logging.info(f"Password reset token for {username} retrieved successfully!")

def delete_password_token(username):
    try:
        result = PW_RESET.delete_one({"_id":username})
        if result.deleted_count == 1:
            print('Password reset token deleted')
        else:
            print('Password reset token not found')    
    except PyMongoError as e:
        logging.error("Error: %s", e)
    else:
        logging.info(f"Password reset token deleted successfully for user {username}")