from fastapi import APIRouter, HTTPException, Depends, status, Query, File, UploadFile, Form, WebSocket, WebSocketDisconnect
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from datetime import timedelta, datetime, timezone
from typing import List, Optional
from models import User, Token, Product, Message
from utils import create_access_token, verify_password, get_password_hash, decode_access_token
from beanie import PydanticObjectId
import asyncio
import aio_pika
from pydantic import BaseModel
import base64
import json
import pytz

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
            message_payload = {"content": message}
            await websocket.send_text(json.dumps(message_payload))


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

                # Send the message to the connected receiver
                await manager.send_personal_message(data.content, data.receiver)



@router.on_event("startup")
async def on_startup():
    asyncio.create_task(consume_messages())


@router.websocket("/ws/{user_id}")
async def websocket_endpoint(websocket: WebSocket, user_id: str):
    token = websocket.query_params.get("token")
    if not token:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    try:
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

    await manager.connect(user_id, websocket)

    # Mark all unread messages for this user as read
    await Message.find(
        {"receiver": username, "read": False}
    ).update_many({"$set": {"read": True}})
    
    try:
        connection = await aio_pika.connect_robust(RABBITMQ_URL)
        channel = await connection.channel()
        while True:
            data = await websocket.receive_text()
            message_data = Message.model_validate_json(data)
            current_timestamp = datetime.now(pytz.utc)

            # Convert to IST
            ist_timezone = pytz.timezone('Asia/Kolkata')
            current_timestamp_ist = current_timestamp.astimezone(ist_timezone)

            # Save the message to the database
            message_to_save = Message(
                sender=message_data.sender,
                receiver=message_data.receiver,
                content=message_data.content,
                timestamp=current_timestamp_ist,
                read=False  # Mark new messages as unread
            )
            await message_to_save.insert()

            # Publish the message to RabbitMQ
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

    current_timestamp = datetime.utcnow()
    ist_timezone = pytz.timezone('Asia/Kolkata')
    current_timestamp_ist = current_timestamp.astimezone(ist_timezone)

    expires_at = current_timestamp_ist + access_token_expires
    new_token = Token(
        username=user.username,
        user_id=user.id,
        access_token=access_token,
        token_type="bearer",
        expires_at=expires_at
    )
    
    await new_token.insert() 

    return new_token  

@router.post("/upload/")
async def upload_product(
    name: str = Form(..., min_length=3, max_length=100),  # name as form field
    description: str = Form(None, max_length=500),  # description as form field (optional)
    images: List[UploadFile] = File(...),  # image as file upload
    current_user: dict = Depends(get_current_user)  # Get the authenticated user (optional)
):
    try:
        image_base64_list = [] 
        for image in images: 
            content = await image.read()
            image_base64 = base64.b64encode(content).decode("utf-8")  
            image_base64_list.append(image_base64)

        # Create a Product instance with Base64 image data
        user_id = PydanticObjectId(current_user.id)
        product = Product(
            name=name,
            description=description,
            image_base64=image_base64_list,  # Store the Base64 string
            user_id= user_id,  # Associate with user
        )

        # Save to MongoDB
        print(f"Product to be inserted: {product.user_id}")
        await product.insert()
        
        return {
            "msg": "Product uploaded successfully",
            "product": {
                "name": product.name,
                "description": product.description,
                "Image_count": len(product.image_base64),
                "user_id": str(current_user.id),
                "Product_ID": str(product.id)
            }
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to upload product: {str(e)}")


@router.get("/MyProducts")
async def get_user_products(
    current_user: dict = Depends(get_current_user)
):
    try:
        user_id = PydanticObjectId(current_user.id)
        
        products = await Product.find(Product.user_id == user_id).to_list()
        
        # Transform the products to include base64 images
        product_list = []
        for product in products:
            product_dict = {
                "product_id": str(product.id),
                "product_name": product.name,
                "description": product.description or "",
                "images": product.image_base64,  # List of base64 encoded images
                "image_count": len(product.image_base64)
            }
            product_list.append(product_dict)
        
        return {
            "total_products": len(product_list),
            "products": product_list
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve products: {str(e)}")
    
@router.get("/products/", response_model=List[dict])
async def get_all_products():
    try:
        products_with_users = []
        async for product in Product.find_all():
            user = await User.get(product.user_id)
            if not user:
                raise HTTPException(status_code=404, detail="User not found for a product.")
            
            product_with_username = {
                "id":str(product.id),
                "name": product.name,
                "description": product.description,
                "image_base64": product.image_base64,
                "user_id": str(product.user_id),
                "username": user.username,  # Include the username from the User model
            }
            products_with_users.append(product_with_username)
        
        return products_with_users

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"An error occurred: {str(e)}")
    
@router.get("/products/{product_id}", response_model=dict)
async def get_product_by_id(product_id: str):
    try:
        # Fetch the product by its ID
        product = await Product.get(product_id)
        if not product:
            raise HTTPException(status_code=404, detail="Product not found.")

        # Fetch the associated user for the product
        user = await User.get(product.user_id)
        if not user:
            raise HTTPException(status_code=404, detail="User not found for the product.")

        # Construct the product details with user information
        product_with_user = {
            "id": str(product.id),  # Include the product ID
            "name": product.name,
            "description": product.description,
            "image_base64": product.image_base64,
            "user_id": str(product.user_id),
            "username": user.username,  # Include the username from the User model
        }

        return product_with_user

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"An error occurred: {str(e)}")

@router.get("/chat-history/{user1}/{user2}", response_model=List[Message])
async def get_chat_history(
    user1: str, 
    user2: str, 
    start_time: datetime = None, 
    end_time: datetime = None
):
    """
    Fetch chat history between two users.
    
    Args:
        user1: First user's ID.
        user2: Second user's ID.
        start_time: Optional start time to filter messages.
        end_time: Optional end time to filter messages.
    
    Returns:
        List of messages exchanged between the two users.
    """
    query = {
        "$or": [
            {"sender": user1, "receiver": user2},
            {"sender": user2, "receiver": user1}
        ]
    }
    if start_time:
        query["timestamp"] = {"$gte": start_time}
    if end_time:
        query["timestamp"] = query.get("timestamp", {})
        query["timestamp"]["$lte"] = end_time

    messages = await Message.find(query).sort("timestamp").to_list()
    if not messages:
        raise HTTPException(status_code=404, detail="No chat history found")

    # Convert each message's timestamp from UTC to IST
    ist_timezone = pytz.timezone('Asia/Kolkata')
    for msg in messages:
        msg.timestamp = msg.timestamp.astimezone(ist_timezone)

    return messages


class Participant(BaseModel):
    id: str
    username: str
    unread_count: int  

@router.get("/chat-participants/{user_id}", response_model=List[Participant])
async def get_chat_participants(user_id: str):
    user = await User.get(PydanticObjectId(user_id))
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    username = user.username

    pipeline = [
        {
            "$match": {
                "$or": [
                    {"sender": username},
                    {"receiver": username}
                ]
            }
        },
        {
            "$project": {
                "chat_partner": {
                    "$cond": [
                        {"$eq": ["$sender", username]},
                        "$receiver",
                        "$sender"
                    ]
                },
                "timestamp": "$timestamp",
                "read": "$read",
                "receiver": "$receiver"
            }
        },
        {
            "$group": {
                "_id": "$chat_partner",
                "last_message_timestamp": {"$max": "$timestamp"},
                "unread_count": {
                    "$sum": {
                        "$cond": [
                            {
                                "$and": [
                                    {"$eq": ["$receiver", username]},
                                    {"$eq": ["$read", False]}
                                ]
                            },
                            1,
                            0
                        ]
                    }
                }
            }
        },
        {
            "$sort": {"last_message_timestamp": -1}
        }
    ]

    # Execute aggregation pipeline
    results = await Message.aggregate(pipeline).to_list()

    participants = []
    for result in results:
        participant_username = result["_id"]
        last_message_timestamp = result["last_message_timestamp"]
        unread_count = result.get("unread_count", 0)

        # Debugging: Check the structure of the result to ensure unread_count is present
        print(f"Debug: {participant_username} unread_count: {unread_count}")

        chat_user = await User.find_one({"username": participant_username})
        if chat_user:
            participants.append({
                "username": chat_user.username,
                "id": str(chat_user.id),
                "last_message_timestamp": last_message_timestamp,
                "unread_count": unread_count  # Ensure unread_count is included
            })

    # Debugging: Check the final list of participants
    print(f"Debug: Participants list: {participants}")
    
    return participants

@router.delete("/delete/{product_id}")
async def delete_product(product_id:PydanticObjectId, current_user: User = Depends(get_current_user)):
    product = await Product.get(product_id)
    if not product:
        raise HTTPException(status_code=404, detail="Product not found")
    await product.delete()
    return {"message":"Product deleted successfully"}