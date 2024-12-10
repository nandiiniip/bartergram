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

uri = f"mongodb+srv://preethanandini175:admin123@cluster0.ig56d.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"

client = AsyncIOMotorClient(uri, tlsCAFile=certifi.where())
db = client.bartergram

async def init_db():
    await init_beanie(database=db, document_models=[User])