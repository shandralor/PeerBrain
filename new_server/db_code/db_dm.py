import datetime
import hashlib
import json
import logging
import os
import secrets

import pymongo
import requests
from db_users import get_user_by_username, get_users
from dotenv import load_dotenv
from pymongo.errors import (ConnectionFailure, DuplicateKeyError,
                            InvalidDocument, PyMongoError)

#---DB COLLECTION INIT---#
client = pymongo.MongoClient("mongodb://localhost:27017/")
PeerbrainDB = client["peerbrain_db"]
DM_MESSAGES = PeerbrainDB["dm_messages"]

#---DM MESSAGE FUNCTIONS---#

def concatenate_usernames(username1:str, username2:str)->str:
    """
    Concatenates two usernames with an underscore between them, after trimming
    them to a maximum of 5 characters each.

    Args:
        username1 (str): The first username.
        username2 (str): The second username.

    Returns:
        str: The concatenated usernames, with an underscore between them.

    """
    # sort usernames alphabetically to ensure consistent ordering
    username1 = username1[:5]
    username2 = username2[:5]
    sorted_usernames = sorted([username1, username2])
    # join sorted usernames with an underscore
    concatenated_usernames = '_'.join(sorted_usernames)
    return concatenated_usernames

def generate_database_key_hash(username1:str, username2:str)->str:
    """
    Generate a reproducible hash key to serve as a database key by concatenating the two input usernames
    alphabetically and hashing the concatenated string using SHA-256 hash function.

    Args:
        username1 (str): The first username to be used for generating the key hash.
        username2 (str): The second username to be used for generating the key hash.

    Returns:
        str: The generated hash key as a hexadecimal string.
    """
    
    # concatenate usernames alphabetically
    concatenated_usernames = concatenate_usernames(username1, username2)
    # hash concatenated usernames using SHA-256 hash function
    hash_object =hashlib.sha256(concatenated_usernames.encode())
    key_hash_hex = hash_object.hexdigest()
    return key_hash_hex

def get_message_status(generated_database_key_hash:str):
    """
    Get the highest order number for a conversation identified by the given database key hash.

    Args:
        generated_database_key_hash (str): The hash value used to identify the conversation in the database.

    Returns:
        int or None: The highest order number for the conversation if it exists, otherwise None.
    """
    try:
        status = DM_MESSAGES.find_one({"key" : generated_database_key_hash})
        if status:
            return max(map(int, status["conversation"].keys()))
    except PyMongoError as e:
        logging.error("Error: %s", e)
    else:
        logging.info(f"Friends list retrieved successfully!")
            
def get_conversation(speaker:str, receiver:str):
    """
    This function retrieves a conversation between two speakers from a MongoDB database collection called DM_MESSAGES.
    The conversation is identified by a unique key generated by hashing the names of the speakers.
    If a conversation is found, it is returned as a JSON string containing a list of dictionaries, where each dictionary represents a message in the conversation and contains the speaker's name and their text message.
    If no conversation is found for the given speakers, an error message is returned.

    Args:
        speaker (str): The name of one of the speakers in the conversation.
        receiver (str): The name of the other speaker in the conversation.

    Returns:
        If a conversation is found, a JSON string representing the conversation.
        If no conversation is found, a dictionary containing an error message.
    """
    conversation_key = generate_database_key_hash(speaker, receiver)
    conversation_object = DM_MESSAGES.find_one({"key" : generated_database_key_hash})
    
    if conversation_object:    
        conversation = conversation_object["conversation"]
        conversation_json_list = []
    
        for key in sorted(conversation.keys()):
            speaker = conversation[key]["speaker"]
            text = conversation[key]['text']
            conversation_json_list.append({"speaker" : speaker, "text" : text})
            
        return json.dumps(conversation_json_list)
    return {"Error" : "No conversation found for those users!"}

def push_message_to_database(speaker:str, receiver:str, message:str):
    """Function that will enter a new conversation in the database in none exists. If it does exist it will update the conversation
    with the newest message."""
    generated_database_key_hash = generate_database_key_hash(speaker, receiver)
    
    order_number = get_message_status(generated_database_key_hash)
    if order_number:
        int_order_number = int(order_number)
        int_order_number += 1
        update = {
            "$push": {
                "conversation": [
                    {
                        str(order_number): {
                        "speaker": speaker,
                        "text": message,
                        "date_time": str(datetime.datetime.utcnow())
                }}
                ] 
            }
        }
        try:
            DM_MESSAGES.update_one({"key": generated_database_key_hash}, update)
        except Exception as error_message:
            logging.exception(error_message)

    else:
        order_number = 1
    
        update = {
            "key": generated_database_key_hash,
            "conversation": [
                {str(order_number): {
                    "speaker": speaker,
                    "text": message,
                    "date_time": str(datetime.datetime.utcnow())
                }
            }]
        }
        try:
            insert_dm =DM_MESSAGES.insert_one(update)
        except DuplicateKeyError as e:
            logging.error("Error: Duplicate key - %s", e)
        except InvalidDocument as e:
            logging.error("Error: Invalid document - %s", e)
        except ConnectionFailure as e:
            logging.error("Error: Database connection failed - %s", e)
        except PyMongoError as e:
            logging.error("Error: %s", e)
        else:
            logging.info("DM successfully uploaded")