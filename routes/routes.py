from fastapi import APIRouter, HTTPException, Depends, status, Query, status, BackgroundTasks
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from datetime import timedelta, datetime, timezone
from typing import List, Optional
from models import User, Token
from utils import create_access_token, verify_password, get_password_hash, decode_access_token
from utils import send_reset_email, generate_reset_token
from beanie import PydanticObjectId
import utils

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

#DELETE USER
@router.delete("/delete-user", response_model=dict)
async def delete_user(
    current_user: User = Depends(get_current_user),
    username: str = Query(..., description="Username to delete"),
    password: str = Query(..., description="Password confirmation")
):
    # Verify the username matches the current user
    if current_user.username != username:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, 
            detail="You can only delete your own account"
        )
    
    # Authenticate the user with the provided password
    authenticated_user = await authenticate_user(username, password)
    if not authenticated_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="Invalid username or password"
        )
    
    # Delete the user
    delete_result = await User.find_one({"username": username}).delete()
    
    # Delete associated tokens
    await Token.find({"username": username}).delete_many()
    
    return {"msg": "User deleted successfully"}

#UPDATE USER PASSWORD
@router.put("/update-password", response_model=dict)
async def update_password(
    current_user: User = Depends(get_current_user),
    old_password: str = Query(..., description="Old password for confirmation"),
    new_password: str = Query(..., description="New password to set", min_length=6)
):
    
    # Verify the old password
    if not verify_password(old_password, current_user.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Old password is incorrect"
        )
    
    # Hash the new password
    hashed_new_password = get_password_hash(new_password)

    # Update the user's password
    current_user.password = hashed_new_password
    await current_user.save()  # Save the updated user to the database

    return {"msg": "Password updated successfully"}

# RESET FORGOT PASSWORD

@router.post("/forgot-password", response_model=dict)
async def forgot_password(
    background_tasks: BackgroundTasks,
    username: str = Query(..., description="Username of the account"),
    user_email: str = Query(..., description="Email address for password reset")
):
    
    # Fetch the user by username
    user = await get_user(username)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    # Generate a reset token
    reset_token = generate_reset_token(username)

    # Set the email address to use for sending the reset email
    recipient_email = user_email

    # Send a reset email in the background
    background_tasks.add_task(send_reset_email, user.username, recipient_email, reset_token)

    return {"msg": "Password reset email sent. Check your inbox."}


@router.post("/reset-password", response_model=dict)
async def reset_password(
    token: str = Query(..., description="Password reset token"),
    new_password: str = Query(..., description="New password to set", min_length=6)
):
   
    try:
        # Decode the token
        payload = utils.jwt.decode(token, utils.SECRET_KEY, algorithms=[utils.ALGORITHM])
        username = payload.get("sub")
        if not username:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid token"
            )
        
        # Fetch the user by username
        user = await get_user(username)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        # Hash the new password and update the user
        hashed_password = get_password_hash(new_password)
        user.password = hashed_password
        await user.save()

        return {"msg": "Password reset successfully"}
    except utils.jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Reset token has expired"
        )
    except utils.jwt.PyJWTError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid token"
        )