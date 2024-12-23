from pydantic import field_validator, Field
from beanie import Document
from typing import Optional
from datetime import datetime

class User(Document):
    username : str = Field(..., title="Username", min_length=3, max_length=50)
    password : str = Field(...,title="Hashed Password")

    class Settings:
        collection="user_data"

class Token(Document):
    username : str = Field(..., title="Username", min_length=3, max_length=50)
    access_token : str = Field(..., title="Access Token")
    token_type : str = Field(..., title="Token Type")
    expires_at: datetime = Field(..., title="Token Expiration Time")

    class Settings:
        collection = "token_data"
