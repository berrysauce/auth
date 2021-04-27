from typing import Optional
from pydantic import BaseModel
from fastapi import FastAPI, HTTPException, Request, Depends, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from deta import Deta
import uuid
from dotenv import load_dotenv
import os
import sentry_sdk
from datetime import date
import secrets
from tools import hashing
import json


# Load Sentry

"""
CHANGE TO SENTRY PROJECT

sentry_sdk.init(
    https://0b626e39891a4dab8a4f191cc88f3469@o309026.ingest.sentry.io/5599097,
    traces_sample_rate=1.0
)
"""

# Setup

load_dotenv()
DETA_TOKEN = os.getenv("DETA_TOKEN")
APP_TOKEN = os.getenv("APP_TOKEN")
APP_USER = os.getenv("APP_USER")
deta = Deta(DETA_TOKEN)  # configure your Deta project
db = deta.Base("users")  # access your DB
app = FastAPI()
security = HTTPBasic()
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

def get_current_username(credentials: HTTPBasicCredentials = Depends(security)):
    correct_username = secrets.compare_digest(credentials.username, APP_USER)
    correct_password = secrets.compare_digest(credentials.password, APP_TOKEN)
    if not (correct_username and correct_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials.username

class CreateUser(BaseModel):
    userid: str
    allowed_apps: Optional[list] = None
    
class CheckUser(BaseModel):
    userid: str
    token: str


@app.get("/")
@limiter.limit("1000/minute")
def read_root(request: Request):
    today = date.today()
    year = str(today.year)
    return {"msg": "API SERVED BY BERRYSAUCE.ME - COPYRIGHT " + year}


@app.post("/check")
@limiter.limit("100/minute")
def read_item(user: CheckUser, request: Request):
    try:
        request = next(db.fetch({"userid": user.userid}))[0]
        if hashing.verifypw(user.token, request["token"]) and request["disabled"] == False:
            return {"valid": True}
        else:
            if request["disabled"] == True:
                reason = "Account was disabled"
            else:
                reason = "The provieded token is invalid"
            return {"valid": False,
                    "reason": reason}
    except:
        raise HTTPException(status_code=404, detail="User not found")


@app.post("/create")
@limiter.limit("10/minute")
def add_item(user: CreateUser, request: Request, username: str = Depends(get_current_username)):
    #try:
    if len(next(db.fetch({"userid": user.userid}))) is 0:
        token = uuid.uuid4().hex
        today = str(date.today())
        db.insert({
            "userid": user.userid,
            "token": hashing.hashpw(token),
            "allowed_apps": user.allowed_apps,
            "date": today,
            "disabled": False
            })
        return {"msg": "Success!",
                "created_by": username,
                "data": {
                    "userid": user.userid,
                    "token": token,
                    "allowed_apps": user.allowed_apps,
                    "date": today}
                }
    else:
        raise HTTPException(status_code=409, detail="User already exists")
    #except:
    #    raise HTTPException(status_code=500, detail="Server error")
    

@app.delete("/delete")
@limiter.limit("5/minute")
def delete_item(user: str, request: Request, username: str = Depends(get_current_username)):
    try:
        dbuser = next(db.fetch({"userid": user}))[0]
        db.delete(dbuser["key"])
        return {"msg": "Success!",
                "deleted_by": username,
                "deleted_user": user}
    except Exception as exception:
        raise HTTPException(status_code=404, detail="Item not found")