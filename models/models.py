from pydantic import field_validator, Field
from beanie import Document
from typing import Optional

class User(Document):
    username : str = Field(..., title="Username", min_length=3, max_length=50)
    password : str = Field(...,title="Hashed Password")

    class Settings:
        collection="user_data"