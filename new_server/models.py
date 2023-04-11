"""Below we will define the necessary pydantic models to use in our application."""
from uuid import UUID, uuid4
from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, EmailStr #pylint: disable=no-name-in-module

class User(BaseModel): # pylint: disable=too-few-public-methods
    """
    Represents a user in our application.

    Attributes:
        username (str): The user's username.
        key (UUID, optional): The user's unique identifier. Defaults to a randomly generated UUID.
        email (EmailStr): The user's email address.
        user_password (str, optional): The user's password. Defaults to None.
        disabled (bool, optional): Whether the user account is disabled. Defaults to False.
        friends (List[str], optional): A list of the user's friends. Defaults to an empty list.
        otp_secret (str, optional): The user's one-time password secret. Defaults to None.
    """
    
    username: str
    email: EmailStr
    user_password : Optional[str]
    disabled: bool = False
    friends: List[str] = []
    otp_secret: Optional[str] = None

class Reader(BaseModel): # pylint: disable=too-few-public-methods
    """A helper class for the message creation process.

    Attributes:
        username (str or None): The username of the reader.
        encrypted_sym_key (str or None): The encrypted symmetric key for the message.
    """
    
    username: str or None = None
    encrypted_sym_key: str or None = None

class Thought(BaseModel): # pylint: disable=too-few-public-methods
    """
    Represents a thought with a username, key, title, content, rating, and creation date.

    Attributes:
        username (str): The username of the author of the thought.
        key (Optional[UUID], optional): The unique identifier of the thought. Defaults to a new UUID4 instance.
        title (str): The title of the thought.
        content (str): The content of the thought.
        rating (Optional[float], optional): The rating of the thought. Defaults to 0.0.
        creation_date (Optional[datetime], optional): The creation date of the thought. Defaults to None.
    """
    
    username: str
    key: Optional[UUID] = uuid4()
    title: str
    content: str
    rating: Optional[float] = 0.0
    creation_date: Optional[datetime]

class Token(BaseModel): # pylint: disable=too-few-public-methods
    """Class defining our JWT token.

    Attributes:
        access_token (str): The access token string.
        token_type (str): The type of token (e.g., "bearer").
    """
    access_token: str
    token_type: str

class TokenData(BaseModel): # pylint: disable=too-few-public-methods
    """
    Helper class for the authentication process.

    Attributes:
        username (str or None): The username associated with the authentication process. Defaults to None.
    """
    
    username: str or None = None

class UserInDB(User): # pylint: disable=too-few-public-methods
    """Helper class for the authentication process.

    This class inherits from the User class and includes an additional property for hashed password.

    Attributes:
        hashed_pw (str): The hashed password for the user.
    """
    hashed_pw: str
    
class PubKey(BaseModel): # pylint: disable=too-few-public-methods
    """
    A class representing a public key.

    Attributes:
        pub_key (str): The string representation of the public key.

    Note:
        This class is a subclass of BaseModel and inherits all its attributes and methods.
    """
    pub_key: str

class KeyStore(BaseModel): # pylint: disable=too-few-public-methods
    """
    A class representing a key store that stores a public key and a symmetric key.

    Attributes:
        pub_key (str): A string representing the public key.
        symmetric_key (str): A string representing the symmetric key.
    """
    pub_key : str
    symmetric_key : str
    
class SymKeyRequest(BaseModel): # pylint: disable=too-few-public-
    """
    A request model for symmetric key exchange between a user and their friend.
    
    Attributes:
    -----------
    user_password : str
        The user's password.
    friend_username : str
        The username of the user's friend.
    """
    user_password : str
    friend_username : str

class PasswordResetUser(BaseModel):
    username : str    
   
class MessageObject(BaseModel):
    friend_username : str 
    message : str
