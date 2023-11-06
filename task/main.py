from fastapi import FastAPI, Request, Depends, Form, status, File,UploadFile
import httpx
import os
import requests
from fastapi.templating import Jinja2Templates
import models
from database import engine, sessionlocal
from sqlalchemy.orm import Session
 
from fastapi import responses
from sqlalchemy.exc import IntegrityError
from fastapi.responses import RedirectResponse
#login module
from datetime import datetime, timedelta
from typing import Union

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel
from typing_extensions import Annotated
from authlib.integrations.starlette_client import OAuth
from starlette.config import Config
from starlette.middleware.sessions import SessionMiddleware

from fastapi.responses import RedirectResponse

  
from users import UserCreateForm
 
models.Base.metadata.create_all(bind=engine)
  
templates = Jinja2Templates(directory="templates")

  
app = FastAPI()

class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: Union[str, None] = None


class User(BaseModel):
    username: str
    email: Union[str, None] = None
    full_name: Union[str, None] = None
    disabled: Union[bool, None] = None

class Details(BaseModel):
    username: str
    email: Union[str, None] = None
    bio: Union[str, None] = None

    


class UserInDB(User):
    hashed_password: str

app.add_middleware(SessionMiddleware, secret_key="G42CSPX-ltbR2DEqKY3jd3N33LcsB7BLKDXz")

def get_db():
    db = sessionlocal()
    try:
        yield db
    finally:
        db.close()
  
@app.get("/")
async def home(request: Request, db: Session = Depends(get_db)):
    return responses.RedirectResponse(
                "/docs", status_code=status.HTTP_302_FOUND
            )
    # return templates.TemplateResponse("register.html", {"request": request})


@app.get("/login")
async def home(request: Request, db: Session = Depends(get_db)):
    return templates.TemplateResponse("login.html", {"request": request})

@app.post("/login")
async def login(request:Request, email: str = Form(...), password: str = Form(...),db : Session = Depends(get_db)):
    user =   authenticate_user(email, password, db)

    if user:
        request.session["username"]=email
        userToken = db.query(models.userToken).filter(models.userToken.email==user.email).first()
        access_token = create_access_token({"username":user.username, "email":user.email, "password":user.password})
        if userToken:
            if not check_token_expiry(userToken.token):
                    userToken.token = access_token
                    db.commit()
        else:
            userToken = models.userToken(username=user.username ,email=user.email, token= access_token)
            db.add(userToken)
            db.commit()

        return {"user ": user.username, "token":access_token}
    
    return {"Invalid Credentials !"}
       
       
    #    oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")




@app.post("/register")
async def register(request: Request, username: str = Form(...), email: str = Form(...), password: str = Form(...),bio:str = Form(...), mobile: str = Form(...) ,file: UploadFile = File(...),db: Session = Depends(get_db)):
    form = UserCreateForm(request)
    await form.load_data()
    if await form.is_valid():
        total_row = db.query(models.Users).filter(models.Users.email == email).first()
        if total_row:
            return {"message":"user allready exists","username": username, "email":email}

        try:
            if total_row == None:
                hashPassword = get_password_hash(password)
                user = models.Users(
                username=username, email=email, password=hashPassword, bio=bio, mobile=mobile
            )
                db.add(user)
                db.commit()
                upload_photo(email, file)  
            return {"message":"User registered successfully ", "username":username,"email":email,"hashedPassword":hashPassword,"bio":bio}

            # return responses.RedirectResponse(
            #     "/login", status_code=status.HTTP_302_FOUND
            # )  # default is post request, to use get request added status code 302
        except IntegrityError:
            # form.__dict__.get("errors").append("Duplicate username or email")
            # return templates.TemplateResponse("register.html", form.__dict__)
            return {"message":"something went wrong while creating users !"}
    return {"message":"User not created, Please check the error","error":"Username and Password length should be >3 and email should be a valid email (abc@gmail.com)"}

def upload_photo( email : str, file: UploadFile = File(...)):
    # Define the destination directory to save the uploaded files
    upload_dir = "userPhoto"
    
    # Create the directory if it doesn't exist
    os.makedirs(upload_dir, exist_ok=True)
    
    # Generate the target filename
    file_location = os.path.join(upload_dir,email+ "_"+file.filename )
    
    # Save the uploaded file
    with open(file_location, "wb") as file_object:
        file_object.write(file.file.read())
    
    return {"filename": email+ "_"+file.filename }

@app.post("/signout")
def sign_out(request: Request,  db: Session = Depends(get_db)):
    # Add your sign-out logic here
    # For example, clearing session or access tokens
    # or any other actions required for sign-out
    #will get the token and extract email from it 
    #delete the entry from userToken
    email = request.session.pop("username", False)
    if not email:
        return {"You are not looged in Yet !"}


    userToken = db.query(models.userToken).filter(models.userToken.email == email).first()
    if userToken:
        db.delete(userToken)
        db.commit()

    return ({"message": "Sign-out successful"})

@app.post("/userDetails")
def userDetails(request: Request,  db: Session = Depends(get_db)):

    email = request.session.get("username", False)

    if not email:
        return {"It's seems you are sign out or your session has expirted, kindly login first to get userdetails "}
    user = db.query(models.Users).filter(models.Users.email == email).first()
    photo = get_files_with_prefix("userPhoto", email)

    if user:
        return {"name": user.username,"email":user.email, "bio":user.bio,"mobile":user.mobile,"photo":photo}
    
    return {"user session is not active"}

def get_files_with_prefix(directory, prefix):
    files = []
    for filename in os.listdir(directory):
        if filename.startswith(prefix):
            files.append(os.path.join(directory, filename))
    return files

def remove_files_with_prefix(directory, prefix):
    for filename in os.listdir(directory):
        if filename.startswith(prefix):
            file_path = os.path.join(directory, filename)
            os.remove(file_path)
            print(f"Deleted file: {file_path}")

@app.put("/updateUsers")
def update_user(request: Request,user_email: str, username : str, password : str, bio: str, mobile: str,  file: UploadFile = File(...), db: Session = Depends(get_db)):
    # Code to update user details, for example, update the user in the database
    errors = {}
    validation = False
    if "@" not in user_email:
        errors["emai"]="Provided email is not a valid format"
        validation = True
    if len(password)<=4:
        errors["password"]="create password with at least 5 digit long"
        validation = True

    if len(username)<=3:
        errors["username"] = "Provided username is too small "
        validation = True

    if validation:
        errors["message"]="User details can not be updated !"
        return errors

    
    email = request.session.get("username", False)

    if not email:
        return {"It's seems you are sign out or your session has expirted, kindly login first to update userdetails "}
    user = db.query(models.Users).filter(models.Users.email == email).first()
    
    if user:
        user.username = username
        user.email = user_email
        hashedpassword = get_password_hash(password)
        user.password = hashedpassword
        user.bio = bio
        user.mobile=mobile
        db.commit()
        remove_files_with_prefix("userPhoto",email )
        uploadFilePath = upload_photo(user_email,file )
        filepath = get_files_with_prefix("userPhoto", user_email)

        # Return the updated user details as a response
        return {"message": f"User {email} updated successfully", "user": {"username ":user.username, "bio":user.bio,"email":user.email,"mobile":user.mobile, "photo":filepath}}
    return {"message":"something went wrong"}

@app.get("/binance")
async def get_binance_data(request: Request):
    url = "https://api.binance.com/api/v3/ticker/24hr"

    email = request.session.get("username", False)
    if not email:
        return {"It's seems you are sign out or your session has expirted, kindly login first to get coin details "}

    async with httpx.AsyncClient() as client:
        response = await client.get(url)
        data = response.json()
        # if len(data)>0:
        #     data = data[:100]
    
    return data


@app.get("/binance_by_symbol")
async def get_binance_data(request: Request, symbol: str, db: Session = Depends(get_db)):
    url = "https://api.binance.com/api/v3/ticker/24hr?symbol="+symbol
    email = request.session.get("username", False)
    if not email:
        return {"It's seems you are sign out or your session has expirted, kindly login first to get coin details "}

    
    async with httpx.AsyncClient() as client:
        response = await client.get(url)
        data = response.json()
    
    return data


@app.get("/wather-report")
async def get_binance_data(request: Request,  db: Session = Depends(get_db)):
    url = "https://api.data.gov.sg/v1/environment/air-temperature"

    email = request.session.get("username", False)
    if not email:
        return {"It's seems you are sign out or your session has expirted, kindly login first to get coin details "}


    
    async with httpx.AsyncClient() as client:
        response = await client.get(url)
        data = response.json()
    api_key = "a2fa6ef5be87b242340ec780cc34bab7"
    result = []
    for address in data["metadata"]["stations"]:
        
        lat = address["location"]["latitude"]
        lon = address["location"]["longitude"]
        obj = get_weather(lat, lon, api_key)
        result.append(obj)
    return result


def get_weather(lat, lon, api_key):
    url = f"https://api.openweathermap.org/data/2.5/weather?lat={lat}&lon={lon}&appid={api_key}"
    response = requests.get(url)
    
    if response.status_code == 200:
        data = response.json()
        place = data['name']
        weather = data['weather'][0]['description']
        return {"place":place, "weather":weather}
    else:
        return None

# Set the latitude, longitude, and API key
# latitude = 37.7749
# longitude = -122.4194


# Call the get_weather function
# place, weather = get_weather(latitude, longitude, api_key)



#login module

# to get a string like this run:
# openssl rand -hex 32
SECRET_KEY = "15a2069ecb087b702ac41f8bda9d6a426592f267112f26530bf758bdbd6638f5"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# app = FastAPI()


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def get_user( email: str,db: Session = Depends(get_db)):
    user = db.query(models.Users).filter(models.Users.email == email).first()

    if user:
        return user
    else:
        return None



def authenticate_user( email: str, password: str,db: Session = Depends(get_db) ):
    user = get_user(email,db)
    if not user:
        return False
    if not verify_password(password, user.password):
        return False
    return user


def create_access_token(data: dict, expires_delta: Union[timedelta, None] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def check_token_expiry(token):
    try:
        decoded_token = jwt.decode(token,SECRET_KEY, algorithms=["HS256"])
        expiry_timestamp = decoded_token.get("exp")
        if expiry_timestamp:
            expiry_datetime = datetime.fromtimestamp(expiry_timestamp)
            current_datetime = datetime.now()
            if expiry_datetime > current_datetime:
                return True
            else:
                return False
        else:
            return False
    except :
        return False

async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)], db : Session= Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    
    # obj= db(models.Users).filter(email = token_data.username).first()
    user = get_user(email=token_data.username)
    if user is None:
        raise credentials_exception
    return user


async def get_current_active_user(
    current_user: Annotated[User, Depends(get_current_user)]
):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user



@app.post("/token", response_model=Token)
async def login_for_access_token(
    form_data: OAuth2PasswordRequestForm=Depends(),db: Session = Depends(get_db)
):
    user = authenticate_user(form_data.username, form_data.password,db)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.email}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}


#login using google and facebook

config = Config('.env')  # read config from .env file
oauth = OAuth(config)
oauth.register(
    name='google',
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={
        'scope': 'openid email profile'
    }
)


# app = FastAPI()

@app.route('/google/login')
async def login(request: Request):
    # absolute url for callback
    # we will define it below
    redirect_uri = request.url_for('auth')
    return await oauth.google.authorize_redirect(request, redirect_uri)

@app.route('/auth')
async def auth(request: Request):
    token = await oauth.google.authorize_access_token(request)
    # user = await oauth.google.parse_id_token(request, token)
    user = token['userinfo']
    #get the user
    #get the all required info and save it in Users table
    return user

