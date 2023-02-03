# -*- coding: utf-8 -*-
"""
Created on Thu Feb  2 22:14:39 2023

@author: Sashank Shekhar Shukla
contact: sashankshekharshukla@gmail.com
"""

'''Swagger UI isn't accepting authorization header, 
so it is passed as string'''

from fastapi import FastAPI, Header, HTTPException
import datetime 
from pydantic import BaseModel
import jwt
from pymongo import MongoClient
import bcrypt

app = FastAPI()

# Hardcoded secret key for JWT. In a real-world scenario, this should be securely stored and not hardcoded.
SECRET_KEY = "Ne23##dgiweoooffmsd232nnWEDE23"

# Connect to the MongoDB database
client = MongoClient("mongodb://localhost:27017/")
db = client["todo_db"]
tasks_collection = db["tasks"]
users_collection = db["users"]

# Task model
class Task(BaseModel):
    description: str
    due_date: str 
    status: str

# User model
class User(BaseModel):
    username: str
    password: str

# Exception for Past time
class PastTimeException(Exception):
    def __init__(self, message="No one can travle into past, please enter correct time"):
        self.message = message

# Login endpoint
@app.post("/login",description="Copy access token and paste to authorization field of other calls" )
async def login(user: User):
    stored_user = users_collection.find_one({"username": user.username})
    try:
        if stored_user is not None and bcrypt.checkpw(user.password.encode(), stored_user["password"].encode()):
            # Generate JWT
            jwt_token = jwt.encode({"user": user.username}, SECRET_KEY, algorithm="HS256")
            return {"access_token": jwt_token}
    except:
        raise HTTPException(status_code=400, detail="Something went wrong.")
    raise HTTPException(status_code=400, detail="Incorrect username or password")

# Register endpoint
@app.post("/register")
async def register(user: User):
    if users_collection.find_one({"username": user.username}) is not None:
        raise HTTPException(status_code=400, detail="Username already exists")
    user.password = bcrypt.hashpw(user.password.encode(), bcrypt.gensalt()).decode()
    users_collection.insert_one(user.dict())
    return {"message": "User created"}

# Task endpoints

# API endpoint to read task
@app.get("/tasks")
async def get_tasks(authorization: str = "None"):
    # Check JWT
    try:
        payload = jwt.decode(authorization, SECRET_KEY, algorithms=["HS256"])
    except (jwt.DecodeError, jwt.ExpiredSignatureError):
        raise HTTPException(status_code=400, detail="Invalid JWT")
    return [task for task in tasks_collection.find({}, {"_id": 0})]

# API endpoint to read tasks by description
@app.get("/tasks/{description}")
async def get_task_by_description(description: str,authorization: str = "None" ):
    # Check JWT
    try:
        payload = jwt.decode(authorization, SECRET_KEY, algorithms=["HS256"])
    except (jwt.DecodeError, jwt.ExpiredSignatureError):
        raise HTTPException(status_code=400, detail="Invalid JWT")
    task = tasks_collection.find_one({"description": description}, {"_id":0})
    if task:
        return task
    else:
        raise HTTPException(status_code=404, detail="Task not found")
        
# API endpoint to read tasks by status
@app.get("/tasks/status/{status}")
async def get_tasks_by_status(status:str, authorization: str = "None"):
    # Check JWT
    try:
        payload = jwt.decode(authorization, SECRET_KEY, algorithms=["HS256"])
    except (jwt.DecodeError, jwt.ExpiredSignatureError):
        raise HTTPException(status_code=400, detail="Invalid JWT")
    return [task for task in tasks_collection.find({"status": status}, {"_id": 0})]

# API endpoint to create tasks
@app.post("/tasks", description="due_date must be in dd/mm/yyyy")
async def create_task(task: Task, authorization: str = "None"):
    # Check JWT
    try:
        payload = jwt.decode(authorization, SECRET_KEY, algorithms=["HS256"])
        day, month, year = task.due_date.split('/')
        due_date = datetime.datetime(int(year), int(month), int(day))
        if due_date < datetime.datetime.now():
            raise PastTimeException()
        test = tasks_collection.find_one({"description": task.description})
        if test != None:
            return {"message":f"Task already exist for {test['due_date']} and status is {test['status']}."}
    # In case of invalid jwt
    except (jwt.DecodeError, jwt.ExpiredSignatureError):
        raise HTTPException(status_code=400, detail="Invalid JWT")
    # If user enter date in incorrect format
    except (ValueError):
        raise HTTPException(status_code=400, detail="date must be in dd/mm/yyyy format")
    # If user trying to create task in past
    except PastTimeException as e:
        raise HTTPException(status_code=400, detail=e.message)
    tasks_collection.insert_one(task.dict())
    return {"message": "Task created"}

# API endpoint to update tasks
@app.put("/tasks")
async def update_task(task: Task, authorization: str = "None"):
    try:
        payload = jwt.decode(authorization, SECRET_KEY, algorithms=["HS256"])
    except (jwt.DecodeError, jwt.ExpiredSignatureError):
        raise HTTPException(status_code=400, detail="Invalid JWT")
    try:
        tasks_collection.update_one({"description": task.description}, {"$set": {"due_date": task.due_date, "status": task.status}})
        return {"message": "Task Updated successfully"}
    except:
        return {"message": "Task Update failed"}

# API endpoint to delete tasks
@app.delete("/tasks")
async def delete_task(description:str, authorization: str = "None"):
    try:
        payload = jwt.decode(authorization, SECRET_KEY, algorithms=["HS256"])
    except (jwt.DecodeError, jwt.ExpiredSignatureError):
        raise HTTPException(status_code=400, detail="Invalid JWT")
    try:
        tasks_collection.delete_one({"description": description})
        return {"message": "Task Deleted successfully"}
    except:
        return {"message": "Task Deletion failed"}
    
