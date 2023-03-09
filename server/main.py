"""This file will contain all the FastAPI logic for our server module. It will leverage the db.py 
and models.py files to supply its functionality."""

import logging
import os
from datetime import datetime, timedelta
from typing import List, Optional, Union
from uuid import UUID, uuid4
import bcrypt
from passlib.context import CryptContext
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException, Path, Query, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt

#---LOCAL IMPORTS---#
from models import KeyStore, PubKey, SymKeyRequest, Thought, Token, TokenData, User, UserInDB
from db import add_friend, change_password, create_thought, create_user, \
    gen_pw_hash, get_encrypted_sym_key, get_friends_by_username, \
        get_public_key, get_thoughts, get_user_by_email, \
            get_user_by_username, get_users, send_keys_to_remote_server
                

#---LOAD ENV VARS---#
load_dotenv()

#---SECURITY SETUP---#
SECRET_KEY = os.environ.get('SECRET_KEY')
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60
pwd_context = CryptContext(schemes =["bcrypt"], deprecated="auto")
oauth_2_scheme = OAuth2PasswordBearer(tokenUrl="token")

#---APP INIT---#
app = FastAPI()

#---LOG AND DEBUG---#
def print_and_log(message:str, username:str)->None:
    """
    Function to log a message with a username to a log file and print it to the console.
    
    Parameters:
    - message (str): The message to be logged and printed.
    - username (str): The username to be included in the log message.
    
    Returns:
    - None
    
    Side Effects:
    - Logs the message to a file named endpoint_log.txt.
    - Prints the log message to the console.
    """
    
    logging.basicConfig(filename='endpoint_log.txt', level=logging.INFO)
    current_datetime = datetime.utcnow()
    formatted_datetime = current_datetime.strftime("%Y-%m-%d %H:%M:%S")
    log_message = f"{formatted_datetime} - {username} : {message}"
    print(log_message)
    logging.info(log_message)

#---DB INIT FROM DB MODULE---#
db = get_users()

#---CONNECTION SECURITY FUNCTIONS---#
def verify_password(plain_text_pw:str, hash_pw:str)->bool:
    """
    Function to verify that a plain text password matches a hashed password.
    
    Parameters:
    - plain_text_pw (str): The plain text password to be verified.
    - hash_pw (str): The hashed password to compare against.
    
    Returns:
    - bool: True if the plain text password matches the hashed password. False otherwise.
    """
        
    return pwd_context.verify(plain_text_pw, hash_pw)

def get_user(db: dict, username: str) -> Union[UserInDB, None]:
    """
    Function to retrieve a user's data from a database given their username.
    
    Parameters:
    - db (dict): The database dictionary to retrieve the user data from.
    - username (str): The username to search for in the database.
    
    Returns:
    - UserInDB: A `UserInDB` object containing the user's data if the user is found in the database.
      Returns `None` if the user is not found in the database.
    """
    
    if username in db:
        user_data = db[username]
        return UserInDB(**user_data)

def authenticate_user(db:dict, username:str, password:str)->Union[bool, dict]:
    """
    Authenticates a user based on a username and password.

    Parameters:
    - db (dict): A dictionary containing user information.
    - username (str): The username of the user to authenticate.
    - password (str): The password of the user to authenticate.

    Returns:
    - If authentication is successful, returns the user object as a dictionary.
    - If authentication fails, returns False.

    Side Effects:
    - None.
    """
    
    user = get_user(db, username)
    if not user:
        return False
    if not verify_password(password, user.hashed_pw):
        return False
    return user

def create_access_token(data:dict, expires_delta:timedelta or None = None)->str:
    """
    Function that generates a JWT access token with an optional expiration time.
    
    Parameters:
    - data (dict): The data to be encoded in the token.
    - expires_delta (timedelta or None): Optional expiration time for the token.
    
    Returns:
    - str: The encoded JWT token as a string.
    """
    
    to_encode = data.copy()
    
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes = 60)
    
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm = ALGORITHM)
    return encoded_jwt

async def get_current_user(token : str = Depends(oauth_2_scheme)):
    """
    Async function that returns the current authenticated user.
    If authentication fails, it raises an HTTPException with a 401 Unauthorized status code.
    
    Parameters:
    - token (str, optional): The JWT token to use for authentication. Defaults to 
    Depends(oauth_2_scheme).
    
    Returns:
    - User: The authenticated user object.
    
    Raises:
    - HTTPException: Raised if the token cannot be validated or the user cannot be found.
    """
    
    credential_exception = HTTPException(
        status_code = status.HTTP_401_UNAUTHORIZED, 
        detail= "Could not validate credentials",
        headers={"WWW-Authenticate":"Bearer"}
        )
        
    try:
        payload = jwt.decode(token, SECRET_KEY,algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise credential_exception
        token_data = TokenData(username=username)
    
    except JWTError:
        raise credential_exception
    
    user=get_user(db, username = token_data.username)
    
    if user is None:
        raise credential_exception
    
    return user

#---optional to check if user status is disabled---#
async def get_current_active_user(current_user: UserInDB = Depends(get_current_user)):
    """
    Async function that returns the current authenticated user if they are active.
    If the user is not active, it raises an HTTPException with a 400 Bad Request status code.
    
    Parameters:
    - current_user (UserInDB, optional): The currently authenticated user object. Defaults to Depends(get_current_user).
    
    Returns:
    - UserInDB: The currently authenticated user object.
    
    Raises:
    - HTTPException: Raised if the authenticated user is not active.
    """
    
    if current_user.disabled:
        raise HTTPException(status_code=400, detail = "Inactive user!")
    return current_user


#---ENDPOINTS---#

#Root route to get token
@app.post("/", response_model=Token)
@app.post("/token", response_model=Token)
async def login_for_access_token(form_data : OAuth2PasswordRequestForm = Depends()):
    """
    Route function that logs a user in and returns a token for access.
    
    Parameters:
    - form_data (OAuth2PasswordRequestForm): The data from the login form containing the user's
    username and password.
    
    Returns:
    - Token: A response model that contains the access token and token type in a dictionary.
    
    Side Effects:
    - Logs a message to a log file using the 'print_and_log()' function.
    """
    
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code = status.HTTP_401_UNAUTHORIZED, detail= "Username/password incorrect!",
                                         headers={"WWW-Authenticate":"Bearer"}) 
    access_token_expires = timedelta(minutes = ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data={"sub" : user.username}, expires_delta=access_token_expires)
    print_and_log("logged in", user.username)
    return {"access_token" : access_token, "token_type" : "bearer"}

@app.post("/api/v1/users")
async def register_user(user : User):
    """
    API endpoint to register a new user account.
    
    Parameters:
    - user (User): A Pydantic model representing the user data to be registered.
    
    Returns:
    - A dictionary containing a message indicating whether the account creation was successful or not.
    
    Side Effects:
    - If successful, creates a new user account in the database using the provided user data.
    - Logs a message to a file indicating that the user account was created.
    """
    
    username  = user.username
    email = user.email
    user_password = user.user_password
    
    print(get_user_by_email(email))
    print(get_user_by_username(username))
    # if get_user_by_email(email) or get_user_by_username(username):
    #     raise HTTPException(status_code=400, detail="A user with that username/email already exists.")
    create_user(username, email, user_password)
    print_and_log("User account created", username)
    return {"Account creation" : "Successful"}

#---AUTH ENDPOINTS---#

@app.get("/api/v1/users")
async def get_all_users(current_user : User = Depends(get_current_active_user)):
    """
    Async function that gets all users from the database.
    Requires an authenticated user with active status.
    
    Parameters:
    - current_user (User, optional): The current authenticated user. Defaults to Depends(get_current_active_user).
    
    Returns:
    - List[User]: A list of all user objects in the database.
    
    Raises:
    - HTTPException: Raised if the current user is not authenticated or is not active.
    """
    
    return get_users()

@app.get("/api/v1/token-test")
async def token_test(current_user : User = Depends(get_current_active_user)):
    """
    Async function that tests the validity of a JWT token by returning a dictionary with a "Token Validity" key.
    If the token is invalid or the user is not active, it raises an HTTPException with a 401 Unauthorized status code.
    
    Parameters:
    - current_user (User, optional): The authenticated user object to use for authorization. 
    Defaults to Depends(get_current_active_user).
    
    Returns:
    - Dict[str, str]: A dictionary with a single "Token Validity" key and a "Verified" value.
    
    Raises:
    - HTTPException: Raised if the token cannot be validated or the user is not active.
    """
    
    print_and_log("requested token and logged in", current_user.username)
    return {"Token Validity": "Verified"}

@app.get("/api/v1/thoughts/{username}")
async def get_thoughts_for_user( username: str, current_user : User = Depends(get_current_active_user)):
    """
    Async function that returns a list of thoughts for the specified user.
    If authentication fails, it raises an HTTPException with a 401 Unauthorized status code.
    
    Parameters:
    - username (str): The username of the user to retrieve thoughts for.
    - current_user (User, optional): The currently authenticated user object. Defaults to Depends(get_current_active_user).
    
    Returns:
    - List[Thought]: A list of Thought objects for the specified user.
    
    Raises:
    - HTTPException: Raised if the authentication fails.
    """
    
    return get_thoughts(username)

@app.get("/api/v1/thoughts/{query_str}")
async def get_thought(query_str : str, current_user : User = Depends(get_current_active_user)):
    """
    Async function to retrieve thoughts based on a query string. Returns a single thought if it matches exactly, 
    or a list of thoughts that match partially with the query string.
    
    Parameters:
    - query_str (str): The query string to use to retrieve thoughts.
    - current_user (User, optional): The authenticated user object. Uses the `get_current_active_user` function to
    retrieve the user. Defaults to None.
    
    Returns:
    - Union[Thought, List[Thought]]: Returns a single Thought object or a list of Thought objects.
    
    Raises:
    - HTTPException: Raised if the user is not authenticated.
    """
    return get_thought(query_str)

@app.get("/api/v1/friends")
async def get_friends( current_user : User = Depends(get_current_active_user)):
    """
    FastAPI endpoint that returns a list of friends for the current authenticated user.
    Uses the get_current_active_user dependency to check that the user is authenticated.
    
    Parameters:
    - current_user (User, optional): The current authenticated user. Defaults to Depends(get_current_active_user).
    
    Returns:
    - List[Friend]: A list of friends for the current user.
    
    Raises:
    - HTTPException: Raised if the user is not authenticated.
    """
    
    return get_friends_by_username(current_user.username)

@app.post("/api/v1/friends/{friend_username}")
async def add_friends( friend_username: str, current_user : User = Depends(get_current_active_user)):
    """
    Async function that adds a friend to the current user's friend list.
    
    Parameters:
    - friend_username (str): The username of the friend to be added.
    - current_user (User): The currently authenticated user.
    
    Returns:
    - Dict[str, Any]: A dictionary with a message indicating that the friend was added.
    
    Raises:
    - HTTPException: Raised if the friend could not be added.
    """
    
    print_and_log("added a friend", current_user.username)
    return add_friend(current_user.username, friend_username)

@app.post("/api/v1/thoughts")
async def create_new_thought(thought : Thought, current_user : User = Depends(get_current_active_user)):
    """
    Endpoint to create a new thought.
    
    Parameters:
    - thought (Thought): The thought to be created, passed as a Pydantic model.
    - current_user (User): The currently authenticated user, passed as a Pydantic model, with the help of the `get_current_active_user` dependency.
    
    Returns:
    - A dictionary with a single key-value pair, where the key is "Thought" and the value is "Successfully created!".
    """
    username = thought.username
    title = thought.title
    content = thought.content
    
    create_thought(username, title, content)
    
    return {"Thought" : "Successfully created!"}

@app.get("/api/v1/me", response_model=User)
async def read_users_me(current_user : User = Depends(get_current_active_user)):
    """
    Async function that returns the details of the current authenticated user.
    If authentication fails, it raises an HTTPException with a 401 Unauthorized status code.
    
    Parameters:
    - current_user (User, optional): The current authenticated user. Defaults to Depends(get_current_active_user).
    
    Returns:
    - User: The authenticated user object.
    
    Raises:
    - HTTPException: Raised if the user cannot be found or is not active.
    """
    
    print_and_log("consulted his user details", current_user.username)
    return current_user

@app.post("/api/v1/post_key_store")
async def post_keystore_user(keystore : KeyStore,  current_user : User = Depends(get_current_active_user)):
    """
    Endpoint to upload a user's public and symmetric keys to a remote server.
    
    Parameters:
    - keystore (KeyStore): A Pydantic model representing the user's public and symmetric keys.
    - current_user (User): The current authenticated user, obtained from the JWT token.
    
    Returns:
    - A dictionary with a single key-value pair, indicating that the public key was uploaded successfully.
    
    Side Effects:
    - Sends the user's public and symmetric keys, along with their username and hashed password, to a remote server.
    - Logs a message indicating that the user uploaded their keys.
    """
    
    public_key = keystore.pub_key
    symmetric_key = keystore.symmetric_key
    username = current_user.username
    hashed_password = get_user_by_username(username)["hashed_pw"]
    
    send_keys_to_remote_server(public_key, symmetric_key, username, hashed_password)
    
    print_and_log("uploaded his/her public and symmetric key", current_user.username)
    return {"PUBLIC KEY" : "UPLOADED"}

@app.post("/api/v1/user_key_request")
async def get_user_key_store(sym_key_req : SymKeyRequest, current_user : User = Depends(get_current_active_user)):
    """
    Endpoint for getting an encrypted symmetric key for a user's friend.
    
    Parameters:
    - sym_key_req (SymKeyRequest): A SymKeyRequest object containing the user's password and the friend's username.
    - current_user (User): A User object representing the currently authenticated user.
    
    Returns:
    - If the friend's username is in the authenticated user's friends list, returns a dictionary containing the encrypted symmetric key.
    - If the friend's username is not in the authenticated user's friends list, returns a dictionary with a "Message" key indicating an error.
    """
    
    username = current_user.username
    password = sym_key_req.user_password
    friend_username = sym_key_req.friend_username
    
    if friend_username in get_friends_by_username(username).keys():
        return get_encrypted_sym_key(username, password, friend_username)
    else:
        return {"Message" : "Error in getting the encrypted key"}
