from motor.motor_asyncio import AsyncIOMotorClient
from beanie import init_beanie
import certifi
import os
from models.models import User
from dotenv import load_dotenv

load_dotenv()
MONGODB_USERNAME = os.getenv("MONGODB_USERNAME")
MONGODB_PASSWORD = os.getenv("MONGODB_PASSWORD")
MONGODB_HOST = os.getenv("MONGODB_HOST")

uri = f"mongodb+srv://{MONGODB_USERNAME}:{MONGODB_PASSWORD}@{MONGODB_HOST}/?retryWrites=true&w=majority&appName=Cluster0"

async def init_db():
    client = AsyncIOMotorClient(uri, tlsCAFile=certifi.where())
    db = client.bartergram
    await init_beanie(database=db, document_models=[User])