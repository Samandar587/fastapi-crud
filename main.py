from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from passlib.context import CryptContext
from jose import JWTError, jwt
from pydantic import BaseModel
from typing import List

app = FastAPI()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Secret key to sign JWT tokens
SECRET_KEY = "your_secret_key"
ALGORITHM = "HS256"

# Hashing password
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Sample user data (for demonstration purposes)
fake_users = {
    "user1": {
        "username": "user1",
        "password": pwd_context.hash("password1")
    }
}

# User model
class User(BaseModel):
    username: str
    password: str

# Token model
class Token(BaseModel):
    access_token: str
    token_type: str

# Function to create a JWT token
def create_token(data: dict):
    to_encode = data.copy()
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# Function to verify password
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

# Function to get a user by username
def get_user(username: str):
    if username in fake_users:
        user_dict = fake_users[username]
        return User(**user_dict)

# Function to authenticate a user
def authenticate_user(username: str, password: str):
    user = get_user(username)
    if user is None:
        return False
    if not verify_password(password, user.password):
        return False
    return user

# Route to get a JWT token
@app.post("/token")
def login_for_access_token(username: str, password: str):
    user = authenticate_user(username, password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = 1800  # Token expiration time in seconds (e.g., 30 minutes)
    access_token = create_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

# Sample protected route to get user details
@app.get("/users/me")
def read_users_me(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload["sub"]
        user = get_user(username)
        if user is None:
            raise credentials_exception
        return user
    except JWTError:
        raise credentials_exception

# Sample route to create a new user
@app.post("/users/")
def create_user(user: User):
    if user.username in fake_users:
        raise HTTPException(status_code=400, detail="User already exists")
    hashed_password = pwd_context.hash(user.password)
    fake_users[user.username] = {"username": user.username, "password": hashed_password}
    return {"message": "User created successfully"}

# Sample route to get all users
@app.get("/users/")
def get_all_users():
    return fake_users.values()

# Sample route to get a specific user by username
@app.get("/users/{username}")
def get_user_by_username(username: str):
    user = get_user(username)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return user

# Sample route to update a user's password
@app.put("/users/{username}")
def update_user_password(username: str, new_password: str):
    user = get_user(username)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    hashed_password = pwd_context.hash(new_password)
    fake_users[username]["password"] = hashed_password
    return {"message": "Password updated successfully"}

# Sample route to delete a user by username
@app.delete("/users/{username}")
def delete_user(username: str):
    user = get_user(username)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    del fake_users[username]
    return {"message": "User deleted successfully"}
