from typing import Union, Optional, List
from fastapi import FastAPI, Path, Query, HTTPException, status, Depends
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from uuid import UUID, uuid4
from datetime import datetime, timedelta
from jose import JWTError, jwt
from passlib.context import CryptContext
from dotenv import load_dotenv
import os
import bcrypt
import logging

#---LOCAL IMPORTS---#
from models import User, Thought, Token, TokenData, UserInDB, PubKey, KeyStore, SymKeyRequest

from db import get_thoughts, get_users, create_user, get_user_by_email, get_user_by_username, create_thought, get_thoughts, \
    get_friends_by_username, add_friend, gen_pw_hash, change_password, get_public_key, upload_public_key, \
        send_keys_to_remote_server, get_encrypted_sym_key

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
def print_and_log(message, username):
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
    """Returns True if password hash matches the plain text password. Returns False otherwise."""
    return pwd_context.verify(plain_text_pw, hash_pw)

def get_user(db:dict, username:str):
    if username in db:
        user_data = db[username]
        return UserInDB(**user_data)

def authenticate_user(db, username:str, password:str):
    user = get_user(db, username)
    if not user:
        return False
    if not verify_password(password, user.hashed_pw):
        return False
    return user

def create_access_token(data:dict, expires_delta:timedelta or None = None):
    to_encode = data.copy()
    
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes = 60)
    
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm = ALGORITHM)
    return encoded_jwt

async def get_current_user(token : str = Depends(oauth_2_scheme)):
    credential_exception = HTTPException(status_code = status.HTTP_401_UNAUTHORIZED, detail= "Could not validate credentials",
                                         headers={"WWW-Authenticate":"Bearer"})
    
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
    if current_user.disabled:
        raise HTTPException(status_code=400, detail = "Inactive user!")
    return current_user
    

#---ENDPOINTS---#

#Root route to get token
@app.post("/", response_model=Token)
@app.post("/token", response_model=Token)
async def login_for_access_token(form_data : OAuth2PasswordRequestForm = Depends()):
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
    return get_users()

@app.get("/api/v1/token-test")
async def token_test(current_user : User = Depends(get_current_active_user)):
    print_and_log("requested token and logged in", current_user.username)
    return {"Token Validity": "Verified"}

@app.get("/api/v1/thoughts/{username}")
async def get_thoughts_for_user( username: str, current_user : User = Depends(get_current_active_user)):
    return get_thoughts(username)

@app.get("/api/v1/thoughts/{query_str}")
async def get_thought(query_str : str, current_user : User = Depends(get_current_active_user)):
    return get_thought(query_str)

@app.get("/api/v1/friends")
async def get_friends( current_user : User = Depends(get_current_active_user)):
    return get_friends_by_username(current_user.username)

@app.post("/api/v1/friends/{friend_username}")
async def add_friends( friend_username: str, current_user : User = Depends(get_current_active_user)):
    print_and_log("added a friend", current_user.username)
    return add_friend(current_user.username, friend_username)

@app.post("/api/v1/thoughts")
async def create_new_thought(thought : Thought, current_user : User = Depends(get_current_active_user)):
    #user_id = thought.user_id
    username = thought.username
    title = thought.title
    content = thought.content
    
    create_thought(current_user.username, title, content)
    
    return {"Thought" : "Successfully created!"}

@app.get("/api/v1/me", response_model=User)
async def read_users_me(current_user : User = Depends(get_current_active_user)):
    print_and_log("consulted his user details", current_user.username)
    return current_user

@app.get("/api/v1/get_pub_key")#==>TO RETIRE?
async def get_public_key_user( current_user : User = Depends(get_current_active_user)):
    pub_key = get_public_key(current_user.username)
    print_and_log("requested his/her pubkey", current_user.username)
    return {"PUBLIC KEY" : pub_key}

@app.get("/api/v1/get_pub_key_friend/{friend_username}")#==>TO RETIRE?
async def get_public_key_friend(friend_username: str, current_user : User = Depends(get_current_active_user)):
    pub_key = get_public_key(friend_username)
    print_and_log("requested his/her pubkey", friend_username)
    return {"PUBLIC KEY" : pub_key}

@app.post("/api/v1/post_pub_key")#==>TO RETIRE?
async def post_public_key_user(pubkey : PubKey,  current_user : User = Depends(get_current_active_user)):
    bytes_key = pubkey.pub_key
    #symmetric_key = keystore.symmetric_key
    username = current_user.username
    
    upload_public_key(bytes_key, username )
    print_and_log("uploaded his/her public key", current_user.username)
    return {"PUBLIC KEY" : "UPLOADED"}

@app.post("/api/v1/post_key_store")
async def post_keystore_user(keystore : KeyStore,  current_user : User = Depends(get_current_active_user)):
    public_key = keystore.pub_key
    symmetric_key = keystore.symmetric_key
    username = current_user.username
    hashed_password = get_user_by_username(username)["hashed_pw"]
    
    send_keys_to_remote_server(public_key, symmetric_key, username, hashed_password)
    
    print_and_log("uploaded his/her public key", current_user.username)
    return {"PUBLIC KEY" : "UPLOADED"}

@app.post("/api/v1/user_key_request")
async def get_user_key_store(sym_key_req : SymKeyRequest, current_user : User = Depends(get_current_active_user)):
    username = current_user.username
    password = sym_key_req.user_password
    friend_username = sym_key_req.friend_username
    
    if friend_username in get_friends_by_username(username).keys():
        return get_encrypted_sym_key(username, password, friend_username)
    else:
        return {"Message" : "Error in getting the encrypted key"}