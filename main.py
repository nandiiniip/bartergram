from fastapi import FastAPI
from configuration import init_db
from contextlib import asynccontextmanager
from utils.utils import create_test_user

@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    await create_test_user()  
    yield

app = FastAPI(lifespan=lifespan)

@app.get("/")
def read_root():
    return {"message": "Welcome to FastAPI!"}