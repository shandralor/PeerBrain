
import json
import logging
import math
from datetime import datetime
from uuid import uuid4
import pymongo
from dotenv import load_dotenv
from pymongo.errors import (ConnectionFailure, DuplicateKeyError,
                            InvalidDocument, PyMongoError)

#---DB COLLECTION INIT---#
client = pymongo.MongoClient("mongodb://localhost:27017/")
PeerbrainDB = client["peerbrain_db"]
THOUGHTS = PeerbrainDB["thoughts"]

#---THOUGHTS COLLECTION FUNCTIONS---#

def calculate_rating_increase(rating:float)->float:
    """
    Helper function that takes a rating float from a Thoughts object and performs a logarithmic calculation on it. The function 
    returns the result of the calculation.

    Parameters: 
        rating: A float representing the rating of a Thoughts object.
    
    Returns: 
        A float representing the result of the logarithmic calculation.
    
    Raises:   
    """
    increase = 1
    base = 2
    if rating <=1:
        rating=1.1
    
    return rating + increase * math.log(rating, base)

def create_thought(username:str, title:str, content:str)->None:
    """
    Create a new thought object with the given `username`, `title`, and `content` parameters. The `rating` field is
    initially set to 0.0, and the `creation_date` field is set to the current date and time in UTC format. The new
    thought object is inserted into the `THOUGHTS` database collection.

    Parameters:
        username (str): The username associated with the thought.
        title (str): The title of the thought.
        content (str): The content of the thought.

    Returns:
        None: If the thought object is successfully inserted into the database.

    Raises:
        InvalidDocument: If the new thought object is invalid.
        ConnectionFailure: If there is a problem with the database connection.
        PyMongoError: If any other error occurs during the insertion process.
    """
    new_thought = {"username" : username,
                   "title" : title, 
                   "key" : str(uuid4()),
                   "content" : content,
                   "rating" : 0.0,
                   "creation_date": str(datetime.utcnow())
                   }
    try:
        create_thought_object  =THOUGHTS.insert_one(new_thought)
        if create_thought_object.acknowledged:
            return
    except InvalidDocument as e:
        logging.error("Error: Invalid document - %s", e)
    except ConnectionFailure as e:
        logging.error("Error: Database connection failed - %s", e)
    except PyMongoError as e:
        logging.error("Error: %s", e)
    else:
        logging.info("User thought inserted with title: %s", new_thought["title"])

def get_thoughts(username:str)->json:
    """Function to retrieve all thoughts that have a given username in their list.


    Parameters:
        username (str): A string representing the username to search for.

    Returns:
        A JSON string containing a list of dictionary objects representing the thoughts containing the given username, 
        or None if no thoughts were found.

    Raises:
        ConnectionFailure: If there is a failure in connecting to the database.
        PyMongoError: If there is an error while accessing the database.
    """
    try:
        thoughts_list = THOUGHTS.find({"username": username})
        result_list_thoughts=[]
        if thoughts_list:
            for thought in thoughts_list:
                result_list_thoughts.append({"title":thought["title"], 
                                             "content" : thought["content"], 
                                             "rating" : thought["rating"],
                                             "key" : thought["key"]
                                             })
        return json.dumps(result_list_thoughts)
        
    except ConnectionFailure as e:
        logging.error("Error: Database connection failed - %s", e)
    except PyMongoError as e:
        logging.error("Error: %s", e)
    else:
        logging.info(f"Thoughts list for user {username} returned successfully!")
    
def update_thought_rating(key:str):
    """
    Update the rating of a thought with a given key by calling the `calculate_rating_increase` function.

    Args:
    - key: A string representing the unique identifier of the thought.

    Returns:
    - None

    Raises:
    - PyMongoError: If there is an error updating the rating of the thought.
    """
    
    thought = THOUGHTS.find_one({"key": key})
    rating = thought["rating"]
    new_rating = calculate_rating_increase(rating)
    
    
    filter = {"key": key}
    update = {"$set" :{"rating" : new_rating}}
    
    try:
        THOUGHTS.update_one(filter, update)
    except PyMongoError as e:
        logging.error("Error: %s", e)
    else:
        logging.info(f"Thought rating successfully uptdated!")
    
def get_thought(query_str:str):
    """Function to find a Thought by title.

    Args:
        query_str (str): The search query to be matched against thought titles in the database.

    Returns:
        str: A JSON-encoded string representing a list of thoughts with matching titles, including their titles, contents, ratings, and keys.

    Raises:
        ConnectionFailure: If a connection to the MongoDB database cannot be established.
        PyMongoError: If an error occurs while querying the MongoDB database collection.
    """
    try:
        thought_list=THOUGHTS.find()
        
        found_thoughts = []
        for thought in thought_list:
            
            if query_str.lower() in thought["title"].lower():
                del thought["_id"]
                found_thoughts.append(thought)
                
        return json.dumps(found_thoughts)        
            
    except ConnectionFailure as e:
        logging.error("Error: Database connection failed - %s", e)
    except PyMongoError as e:
        logging.error("Error: %s", e)
    else:
        logging.info(f"Thoughts list for query {query_str} returned successfully!") 
      
    