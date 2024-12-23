from fastapi import APIRouter, HTTPException, Depends, status, Query, WebSocket, WebSocketDisconnect
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from datetime import timedelta, datetime, timezone
from typing import List, Optional
from models import User, Token
from utils import create_access_token, verify_password, get_password_hash, decode_access_token
from beanie import PydanticObjectId
import asyncio
import aio_pika
from pydantic import BaseModel

router = APIRouter()

ACCESS_TOKEN_EXPIRE_MINUTES = 30
RABBITMQ_URL = "amqp://guest:guest@localhost/"
QUEUE_NAME = "chat_queue"

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

async def get_user(username: str) -> Optional[User]:
    return await User.find_one({"username": username})

async def authenticate_user(username: str, password: str):
    user = await get_user(username)
    if not user or not verify_password(password, user.password):
        return False
    return user

async def get_current_user(token: str = Depends(oauth2_scheme)):
    payload = decode_access_token(token)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    username: str = payload.get("sub")
    if username is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    user = await get_user(username)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user

class Message(BaseModel):
    sender: str
    receiver: str
    content: str


class ConnectionManager:
    def __init__(self):
        self.active_connections: dict[str, WebSocket] = {}

    async def connect(self, user_id: str, websocket: WebSocket):
        await websocket.accept()
        self.active_connections[user_id] = websocket

    def disconnect(self, user_id: str):
        if user_id in self.active_connections:
            del self.active_connections[user_id]

    async def send_personal_message(self, message: str, user_id: str):
        websocket = self.active_connections.get(user_id)
        if websocket:
            await websocket.send_text(message)


manager = ConnectionManager()


async def consume_messages():
    connection = await aio_pika.connect_robust(RABBITMQ_URL)
    async with connection:
        channel = await connection.channel()
        queue = await channel.declare_queue(QUEUE_NAME, durable=True)

        async for message in queue.iterator():
            async with message.process():
                message_body = message.body.decode()
                print(f"Message received: {message_body}")
                data = Message.model_validate_json(message_body)
                await manager.send_personal_message(data.content, data.receiver)


@router.on_event("startup")
async def on_startup():
    asyncio.create_task(consume_messages())


@router.websocket("/ws/{user_id}")
async def websocket_endpoint(websocket: WebSocket, user_id: str):
    # Manually extract the token from the query parameters
    token = websocket.query_params.get("token")
    if not token:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    try:
        # Validate the token and get the current user
        payload = decode_access_token(token)
        if not payload:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

        username = payload.get("sub")
        if username != user_id:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User mismatch")
    except Exception as e:
        print(f"Authentication failed: {e}")
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    # Proceed with WebSocket connection
    await manager.connect(user_id, websocket)
    try:
        connection = await aio_pika.connect_robust(RABBITMQ_URL)
        channel = await connection.channel()
        while True:
            data = await websocket.receive_text()
            message = Message.model_validate_json(data)
            await channel.default_exchange.publish(
                aio_pika.Message(body=data.encode()), routing_key=QUEUE_NAME
            )
    except WebSocketDisconnect:
        manager.disconnect(user_id)
    except Exception as e:
        print(f"Error: {e}")
        manager.disconnect(user_id)


@router.post("/register", response_model=dict)
async def register(user: User):
    existing_user = await get_user(user.username)
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already registered")

    hashed_password = get_password_hash(user.password)
    new_user = User(username=user.username, password=hashed_password)
    await new_user.insert()
    
    return {"msg": "User registered successfully"}

@router.post("/login", response_model=Token)
@router.post("/login", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = await authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
   
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )

    expires_at = datetime.now(timezone.utc) + access_token_expires
    new_token = Token(
        username=user.username,
        access_token=access_token,
        token_type="bearer",
        expires_at=expires_at
    )
    
    await new_token.insert()  # You are storing the token in the database.

    # Return the full Token model (including username, access_token, token_type, and expires_at)
    return new_token  # Return the whole token object
