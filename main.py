from fastapi import FastAPI
from configuration import init_db
from contextlib import asynccontextmanager
from starlette.middleware import Middleware
from starlette.middleware.cors import CORSMiddleware

@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    yield

app = FastAPI(lifespan=lifespan)

middleware = [
    Middleware(
        CORSMiddleware,
        allow_origins= ["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
]

from routes import router

app.include_router(router)