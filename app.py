from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
import sqlite3
from datetime import datetime, timedelta
from jose import JWTError, jwt
from fastapi.middleware.cors import CORSMiddleware
import secrets
import os

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://frontend-five-silk-24.vercel.app", "http://localhost:8080"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

SECRET_KEY = secrets.token_urlsafe(32)
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

class Profile(BaseModel):
    name: str
    surname: str
    blood_type: str
    allergies: str
    contraindications: str
    contacts: list[dict]
    last_updated: str = datetime.now().isoformat()

class User(BaseModel):
    username: str
    password: str

# БД
conn_users = sqlite3.connect('users.db')
c_users = conn_users.cursor()
c_users.execute('''CREATE TABLE IF NOT EXISTS users
                  (id TEXT PRIMARY KEY, username TEXT UNIQUE, password TEXT)''')
conn_users.commit()

conn_profiles = sqlite3.connect('profiles.db')
c_profiles = conn_profiles.cursor()
c_profiles.execute('''CREATE TABLE IF NOT EXISTS profiles
                     (id TEXT PRIMARY KEY, user_id TEXT, name TEXT, surname TEXT, blood_type TEXT, allergies TEXT, contraindications TEXT, contacts TEXT, last_updated TEXT)''')
conn_profiles.commit()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if not username:
            raise HTTPException(status_code=401, detail="Invalid token")
        c_users.execute("SELECT id, username FROM users WHERE username=?", (username,))
        user = c_users.fetchone()
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        return {"id": user[0], "username": user[1]}
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

@app.post("/register")
async def register(user: User):
    user_id = secrets.token_urlsafe(16)
    c_users.execute("SELECT * FROM users WHERE username=?", (user.username,))
    if c_users.fetchone():
        raise HTTPException(status_code=400, detail="Username already exists")
    c_users.execute("INSERT INTO users (id, username, password) VALUES (?, ?, ?)",
                    (user_id, user.username, user.password))
    conn_users.commit()
    return {"message": "User registered", "user_id": user_id}

@app.post("/token")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    c_users.execute("SELECT id, username FROM users WHERE username=? AND password=?",
                    (form_data.username, form_data.password))
    user = c_users.fetchone()
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    access_token = create_access_token(data={"sub": user[1]})
    return {"access_token": access_token, "token_type": "bearer", "user_id": user[0]}

@app.get("/api/profile/{profile_id}")
async def get_profile(profile_id: str):
    c_profiles.execute("SELECT * FROM profiles WHERE id=?", (profile_id,))
    row = c_profiles.fetchone()
    if row:
        return {
            "id": row[0],
            "name": row[2],
            "surname": row[3],
            "blood_type": row[4],
            "allergies": row[5],
            "contraindications": row[6],
            "contacts": eval(row[7]),
            "last_updated": row[8]
        }
    raise HTTPException(status_code=404, detail="Profile not found")

@app.post("/api/profile/{profile_id}")
async def update_profile(profile_id: str, profile: Profile, current_user: dict = Depends(get_current_user)):
    contacts_str = str(profile.contacts)
    c_profiles.execute('''INSERT OR REPLACE INTO profiles (id, user_id, name, surname, blood_type, allergies, contraindications, contacts, last_updated)
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                      (profile_id, current_user["id"], profile.name, profile.surname, profile.blood_type, profile.allergies, profile.contraindications, contacts_str, profile.last_updated))
    conn_profiles.commit()
    return {"message": "Profile updated"}

@app.get("/api/my-profile")
async def get_my_profile(current_user: dict = Depends(get_current_user)):
    c_profiles.execute("SELECT * FROM profiles WHERE user_id=?", (current_user["id"],))
    row = c_profiles.fetchone()
    if row:
        return {
            "id": row[0],
            "name": row[2],
            "surname": row[3],
            "blood_type": row[4],
            "allergies": row[5],
            "contraindications": row[6],
            "contacts": eval(row[7]),
            "last_updated": row[8]
        }
    raise HTTPException(status_code=404, detail="Profile not found")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))