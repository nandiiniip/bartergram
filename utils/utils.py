from datetime import datetime, timedelta, timezone
from jose import JWTError, jwt
from passlib.context import CryptContext
from email.mime.text import MIMEText
import smtplib

SECRET_KEY = "62B5E8EB0EF708E995E9CC12287F64E2613C1FC34D749D992C2C3444B4261A12" 
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def get_password_hash(password: str):
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def decode_access_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        return None

#Generate a JWT token for password reset

def generate_reset_token(username: str):
    expires_delta = timedelta(minutes=15)  # Token valid for 15 minutes
    expire = datetime.now(timezone.utc) + expires_delta
    payload = {
        "sub": username,
        "exp": expire
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)      
    


#Send a password reset email to the user

def send_reset_email(username: str, user_email: str, reset_token: str):
    RESET_URL = "http://localhost:8000/reset-password?token={token}"  # Replace with your frontend URL

    reset_link = RESET_URL.format(token=reset_token)
    subject = "Password Reset Request"
    body = f"Hi {username},\n\nClick the link below to reset your password:\n{reset_link}\n\nIf you did not request this, ignore this email."
    
    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = "noreply@yourdomain.com"
    msg["To"] = user_email  # Send to the provided user email
    
    with smtplib.SMTP("smtp.gmail.com", 587) as server:
        server.starttls()
        server.login("roselynnannchacko@gmail.com", "Roselyn@140297")
        server.sendmail("roselynnannchacko@gmail.com", user_email, msg.as_string())