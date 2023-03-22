import html
import logging
import os
import sys
from datetime import datetime, timedelta
from typing import List, Optional, Union
from uuid import UUID, uuid4

import bcrypt
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, Form, HTTPException, Path, Query, status
from fastapi.responses import HTMLResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext

sys.path.append('./db_code')
sys.path.append('./email_code')

import db_pw_reset, db_users, db_dm, db_friends, db_keys
from models import (KeyStore, 
                    PubKey, 
                    SymKeyRequest, 
                    Thought, 
                    Token, 
                    TokenData, 
                    User, 
                    UserInDB, 
                    PasswordResetUser, 
                    MessageObject)

#---LOAD ENV VARS---#
load_dotenv()

#---SECURITY SETUP---#
SECRET_KEY = os.environ.get('SECRET_KEY')
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60
pwd_context = CryptContext(schemes =["bcrypt"], deprecated="auto")
oauth_2_scheme = OAuth2PasswordBearer(tokenUrl="token")
RESET_PASSWORD_ROUTE = os.environ.get("RESET_PASSWORD_ROUTE")

#---APP INIT---#
app = FastAPI()

#---DB INIT FROM DB MODULE---#
db = db_users.get_users()

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
    db = db_users.get_users()
    if username in db:
        #username below needs to become keys if the database object for user gets changed
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
    db = db_users.get_users()
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
    db = db_users.get_users()
    
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

#---PUBLIC ENDPOINTS---#

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
    db = db_users.get_users()
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code = status.HTTP_401_UNAUTHORIZED, detail= "Username/password incorrect!",
                                         headers={"WWW-Authenticate":"Bearer"}) 
        
    if user.disabled:
        raise HTTPException(status_code = status.HTTP_401_UNAUTHORIZED, detail= "Account inactive!",
                                         headers={"WWW-Authenticate":"Bearer"})
        
    access_token_expires = timedelta(minutes = ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data={"sub" : user.username}, expires_delta=access_token_expires)
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
    
    username = user.username
    email = user.email
    user_password = user.user_password
    
    print(db_users.get_user_by_email(email))
    print(db_users.get_user_by_username(username))
    if db_users.get_user_by_email(email)== {'Email': 'No user with email found'} and db_users.get_user_by_username(username)=={'Username': 'No user with username found'}:
      db_users.create_user(username, email, user_password)
      return {"Account creation" : "Successful"}
    else:
      raise HTTPException(status_code=400, detail="A user with that username/email already exists.")
    
@app.get("/confirm-email")
async def confirm_email(token: str, username: str):
    """User endpoint that wil handle user verification after the account gets created. If will verify the confirmation token."""
    user =db_users.get_user_by_username(username)
    user_confirm_token = user["confirmation_token"]
    
    if token == user_confirm_token:
        db_users.confirm_registration_token(username)
        html_content = f"""<!DOCTYPE html>
            <html lang="en">

            <head>
                
                <meta charset="utf-8">
                <title>PeerBrain</title>
                <meta name="viewport" content="width=device-width, initial-scale=2.0, user-scalable=0, minimal-ui">
                <meta http-equiv="X-UA-Compatible" content="IE=edge" />

                <link rel="stylesheet" href="https://appsrv1-147a1.kxcdn.com/dattaable/plugins/animation/css/animate.min.css">
                <link rel="stylesheet" href="https://appsrv1-147a1.kxcdn.com/dattaable/css/style.css">
                <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/4.7.0/css/font-awesome.min.css">
                <link rel="stylesheet" href="https://andrewstech.github.io/public/peer-brain/style.css">

                

            </head>

            <body>
                
                
                <div class="auth-wrapper">
                    <div class="auth-content">
                        <div class="auth-bg">
                            <span class="r"></span>
                            <span class="r s"></span>
                            <span class="r s"></span>
                            <span class="r"></span>
                        </div>
                        <div class="card">
                            <div class="card-body text-center">
                                <p class="mb-0 text-muted disabled"><a href="" class="large">Peer Brain</a></p>
                                <div>
                                    <hr>
                                    <p class="mt-2 text-muted disabled"><a href="" disabled>Email verification succesful!</a></p>
                                    <p class="mt-2 text-muted disabled"><a href="" disabled>Your account is now active!</a></p>
                                    <hr>
                                </div>

                                <br />
                                <br />

                                

                                <a class="fa fa-github" style="font-size:24px" href="https://github.com/shandralor/PeerBrain"></a>
                                <br />
                            </div>
                        </div>
                    </div>
                </div>
                 </body>
            </html>"""
        return HTMLResponse(content=html_content, status_code=200)     
        
    else:
        html_content = f"""<!DOCTYPE html>
            <html lang="en">

            <head>
                
                <meta charset="utf-8">
                <title>PeerBrain</title>
                <meta name="viewport" content="width=device-width, initial-scale=2.0, user-scalable=0, minimal-ui">
                <meta http-equiv="X-UA-Compatible" content="IE=edge" />

                <link rel="stylesheet" href="https://appsrv1-147a1.kxcdn.com/dattaable/plugins/animation/css/animate.min.css">
                <link rel="stylesheet" href="https://appsrv1-147a1.kxcdn.com/dattaable/css/style.css">
                <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/4.7.0/css/font-awesome.min.css">
                <link rel="stylesheet" href="https://andrewstech.github.io/public/peer-brain/style.css">

                

            </head>

            <body>
                
                
                <div class="auth-wrapper">
                    <div class="auth-content">
                        <div class="auth-bg">
                            <span class="r"></span>
                            <span class="r s"></span>
                            <span class="r s"></span>
                            <span class="r"></span>
                        </div>
                        <div class="card">
                            <div class="card-body text-center">
                                <p class="mb-0 text-muted disabled"><a href="" class="large">Peer Brain</a></p>
                                <div>
                                    <hr>
                                    <p class="mt-2 text-muted disabled"><a href="" disabled>Email verification was already completed!</a></p>
                                    <hr>
                                </div>

                                <br />
                                <br />

                                

                                <a class="fa fa-github" style="font-size:24px" href="https://github.com/shandralor/PeerBrain"></a>
                                <br />
                            </div>
                        </div>
                    </div>
                </div>


            </body>
            </html>"""
        return HTMLResponse(content=html_content, status_code=200) 

@app.post("/get_password_reset_token")
async def get_password_reset_token(user : PasswordResetUser):    
    username  = user.username
    
    user_object = db_users.get_user_by_username(username)
            
    if user_object == {'Username': 'No user with username found'}:
        raise HTTPException(status_code=400, detail="No user for that username!")
    else:
        if db_pw_reset.get_password_token(username):
            """As the database operation called is a put, it will overwrite the previous token, 
            thus making sure that only one password reset token can exist at any given time."""
            
            print("Reset token already found, deleting previous token!")
        email = user_object["email"]
        db_pw_reset.create_password_reset_token(username, email)
        #Added return to notify user that the email got sent out!
        return {"Password Reset Email Sent Successfully!" : f"Email sent to {email}"}
      
@app.get(f"/{RESET_PASSWORD_ROUTE}/reset-password")  
async def reset_user_password(username:str, token:str):
    """Returns endpoint that will render an html form where you can enter your new password and confirm password. This data will get
    html sanitized and then send to the post endpoint to trigger the function or not."""
    password_token_object = db_pw_reset.get_password_token(username)
    
    if password_token_object and password_token_object["reset_token"] == token:
        print("Matching password reset token found!")
        db_pw_reset.delete_password_token(username)
        html_content = f"""
        <html>
            <head>
    
            <meta charset="utf-8">
            <title>PeerBrain</title>
            <meta name="viewport" content="width=device-width, initial-scale=2.0, user-scalable=0, minimal-ui">
            <meta http-equiv="X-UA-Compatible" content="IE=edge" />

            <link rel="stylesheet" href="https://appsrv1-147a1.kxcdn.com/dattaable/plugins/animation/css/animate.min.css">
            <link rel="stylesheet" href="https://appsrv1-147a1.kxcdn.com/dattaable/css/style.css">

            

        </head>

        <body>
            
            
            <div class="auth-wrapper">
                <div class="auth-content">
                    <div class="auth-bg">
                        <span class="r"></span>
                        <span class="r s"></span>
                        <span class="r s"></span>
                        <span class="r"></span>
                    </div>
                    <div class="card">
                        <div class="card-body text-center">
                            <p class="mb-0 text-muted disabled"><a href="" class="large">Peer Brain</a></p>
                            <div>
                                <p class="mb-0 text-muted disabled"><a href="" disabled>Password Reset</a></p>
                                    <form action="/{RESET_PASSWORD_ROUTE}/submit" method="post">
                                        <input type= "hidden" id = "username" name = "username" value = "{username}">
                                        <input type= "hidden" id = "token" name = "token" value = "{token}">
                                        <label for="fname">New Password:</label><br>
                                        <input type="password" id="new_password" name="new_password" minlength="8" required><br>
                                        <label for="lname">Confirm Password:</label><br>
                                        <input type="password" id="confirm_password" name="confirm_password" minlength="8" required><br><br>
                                        <input type="submit" value="Submit">
                                    </form> 
                            </div>
                            <br />
                            <br />
                            <p class="mb-0 text-muted"> <a href="https://github.com/shandralor/PeerBrain" >GitHub</a></p>
                            <br />
                        </div>
                    </div>
                </div>
            </div>
        </body>
                </html>
        """.format(
            new_password = html.escape(""),
            confirm_password = html.escape(""),
            token = html.escape(""),
            username = html.escape("")
        )
        return HTMLResponse(content=html_content, status_code=200)     
        
    else:
        raise HTTPException(status_code=400, detail="Invalid/expired password reset token!")
      
@app.post(f"/{RESET_PASSWORD_ROUTE}/submit")
async def submit_form(new_password: str = Form(...), confirm_password: str = Form(...), token: str = Form(...), username:str = Form(...)):
    """Post function that will trigger the reset password function if the new password and confirm password match"""
    if new_password != confirm_password:
        raise HTTPException(status_code=400, detail="Passwords did not match!")
    else:               
        db_users.change_password(username, new_password)
        html_content = f"""<!DOCTYPE html>
            <html lang="en">

            <head>
                
                <meta charset="utf-8">
                <title>PeerBrain</title>
                <meta name="viewport" content="width=device-width, initial-scale=2.0, user-scalable=0, minimal-ui">
                <meta http-equiv="X-UA-Compatible" content="IE=edge" />

                <link rel="stylesheet" href="https://appsrv1-147a1.kxcdn.com/dattaable/plugins/animation/css/animate.min.css">
                <link rel="stylesheet" href="https://appsrv1-147a1.kxcdn.com/dattaable/css/style.css">
                <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/4.7.0/css/font-awesome.min.css">
                <link rel="stylesheet" href="https://andrewstech.github.io/public/peer-brain/style.css">

                

            </head>

            <body>
                
                
                <div class="auth-wrapper">
                    <div class="auth-content">
                        <div class="auth-bg">
                            <span class="r"></span>
                            <span class="r s"></span>
                            <span class="r s"></span>
                            <span class="r"></span>
                        </div>
                        <div class="card">
                            <div class="card-body text-center">
                                <p class="mb-0 text-muted disabled"><a href="" class="large">Peer Brain</a></p>
                                <div>
                                    <hr>
                                    <p class="mt-2 text-muted disabled"><a href="" disabled>Password changed successfully!</a></p>
                                    <p class="mt-2 text-muted disabled"><a href="" disabled>You can now login with your new password!!</a></p>
                                    <hr>
                                </div>

                                <br />
                                <br />

                                

                                <a class="fa fa-github" style="font-size:24px" href="https://github.com/shandralor/PeerBrain"></a>
                                <br />
                            </div>
                        </div>
                    </div>
                </div>
                 </body>
            </html>"""
        return HTMLResponse(content=html_content, status_code=200)     
      
#---AUTH ENDPOINTS---#

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
    
    # print_and_log("requested token and logged in", current_user.username)
    return {"Token Validity": "Verified"}

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
    
    return current_user


