from fastapi import APIRouter, HTTPException, Depends, status, Query, File, UploadFile, Form
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from datetime import timedelta, datetime, timezone
from typing import List, Optional
from models import User, Token, Product
from utils import create_access_token, verify_password, get_password_hash, decode_access_token
from beanie import PydanticObjectId
from pathlib import Path
import base64
import shutil

router = APIRouter()

ACCESS_TOKEN_EXPIRE_MINUTES = 30

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

    expires_at = datetime.now(timezone.utc) + access_token_expires
    new_token = Token(
        username=user.username,
        access_token=access_token,
        token_type="bearer",
        expires_at=expires_at
    )
    
    await new_token.insert()

    return {"access_token": access_token, "token_type": "bearer"}

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


@router.get("/user/{user_id}/products")
async def get_product_count_by_user(user_id: str):
    try:
        user_id_obj = PydanticObjectId(user_id)

        products = await Product.find({"user_id": user_id_obj}).to_list()

        if not products:
            raise HTTPException(status_code=404, detail="No products found for this user")

        return {"user_id": user_id, "product_count": len(products)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching products: {str(e)}")


# @router.get("/products/{product_name}/images")
# async def get_images_by_name(product_name: str):
#     # Fetch all products from the database by the product name
#     products = await Product.find({"name": product_name}).to_list()

#     if not products:
#         raise HTTPException(status_code=404, detail="No products found with this name")

#     # Prepare the result with image URLs for all products
#     result = []
#     for product in products:
#         image_paths = product.image_base64
#         if not image_paths:
#             continue

#         result.append({
#             "product_name": product.name,
#             "product_id": str(product.id),
#             "image_urls": [f"/products/{product.name}/image/{Path(image).name}" for image in image_paths]
#         })

#     return {"products": result}