from typing import Optional
from pydantic import BaseModel
import uvicorn
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
import secure


# Load Sentry

import sentry_sdk
sentry_sdk.init(
    "https://6a0a18149aec4ee292e49b18d937b339@o309026.ingest.sentry.io/5738512",
    traces_sample_rate=1.0
)

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
secure_headers = secure.Secure()

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
    app_identifier: Optional[str] = None


@app.middleware("http")
async def set_secure_headers(request, call_next):
    response = await call_next(request)
    secure_headers.framework.fastapi(response)
    return response

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
        request = db.fetch({"userid": user.userid}).items[0]
        
        if user.app_identifier != None:
            if user.app_identifier in request["allowed_apps"]:
                allowed = True
            elif user.app_identifier not in request["allowed_apps"]:
                allowed = False
        else:
            allowed = None
        
        if hashing.verifypw(user.token, request["token"]) and request["disabled"] is False and allowed is None:
            return {"valid": True}
        elif hashing.verifypw(user.token, request["token"]) and request["disabled"] is False and allowed is True:
            return {"valid": True,
                    "checked_for": str(user.app_identifier)}
        else:
            if request["disabled"] is True:
                reason = "User was disabled"
            elif allowed is False:
                reason = "User is not authorized for this app"
            else:
                reason = "The provieded token is invalid"
            return {"valid": False,
                    "reason": reason}
    except:
        raise HTTPException(status_code=404, detail="User not found")


@app.post("/create")
@limiter.limit("10/minute")
def add_item(user: CreateUser, request: Request, username: str = Depends(get_current_username)):
    try:
        if len(db.fetch({"userid": user.userid}).items) == 0:
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
    except Exception as exception:
        raise HTTPException(status_code=500, detail="Server error - {0}".format(exception))
    

@app.delete("/delete")
@limiter.limit("5/minute")
def delete_item(user: str, request: Request, username: str = Depends(get_current_username)):
    try:
        dbuser = db.fetch({"userid": user}).items[0]
        db.delete(dbuser["key"])
        return {"msg": "Success!",
                "deleted_by": username,
                "deleted_user": user}
    except Exception as exception:
        raise HTTPException(status_code=404, detail="Item not found")
    

if __name__ == "__main__":
    uvicorn.run(app, host="localhost", port=80)