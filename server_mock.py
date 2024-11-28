from fastapi import FastAPI, HTTPException, Depends, Query, Path, Body
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel
from typing import List, Optional
from hashlib import sha256
from starlette.status import HTTP_401_UNAUTHORIZED

app = FastAPI(
    title="Southbound API",
    description="API to manage resources with Basic Auth using southbound paths.",
    version="1.0.0",
)

# Basic Auth configuration
security = HTTPBasic()

# Mock user database
USER_DB = {
    "admin": sha256("password123".encode()).hexdigest(),  # Replace with secure storage
}

# Authentication function
def authenticate(credentials: HTTPBasicCredentials = Depends(security)):
    username = credentials.username
    password_hash = sha256(credentials.password.encode()).hexdigest()
    if username not in USER_DB or USER_DB[username] != password_hash:
        raise HTTPException(
            status_code=HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic"},
        )
    return username

# Models
class NewResource(BaseModel):
    name: str
    description: Optional[str] = None
    start_date: str
    end_date: str
    status: str

class Resource(BaseModel):
    id: str
    name: str
    description: str
    start_date: str
    end_date: str
    status: str

class NewTask(BaseModel):
    title: str
    description: Optional[str] = None
    resource_id: str
    assigned_to: Optional[str] = None
    due_date: Optional[str] = None

class Task(BaseModel):
    id: str
    title: str
    description: str
    assigned_to: str
    due_date: str
    status: str

# Southbound paths as defined in the configuration
@app.get("/v1/resources", response_model=List[Resource])
def get_resources(username: str = Depends(authenticate)):
    return [
        {
            "id": "resource-123",
            "name": "Resource 1",
            "description": "Details",
            "start_date": "2024-01-01",
            "end_date": "2024-12-31",
            "status": "active",
        }
    ]

@app.post("/v1/resources", response_model=Resource, status_code=201)
def create_resource(resource: NewResource, username: str = Depends(authenticate)):
    return {"id": "resource-456", **resource.dict()}

@app.get("/v1/resources/{resource_id}", response_model=Resource)
def get_resource_details(
    resource_id: str = Path(..., description="ID of the resource"),
    username: str = Depends(authenticate)
):

    return {
        "id": resource_id,
        "name": "Resource 1",
        "description": "Details",
        "start_date": "2024-01-01",
        "end_date": "2024-12-31",
        "status": "active",
    }

@app.post("/v1/resources/tasks", response_model=Task, status_code=201)
def create_task(task: NewTask, username: str = Depends(authenticate)):
    return {"id": "task-789", **task.dict(), "status": "pending"}

@app.get("/v1/resources/users/{user_id}/information", response_model=List[Task])
def get_user_information(
    user_id: str = Path(..., description="User ID"),
    username: str = Depends(authenticate)
):
    return [
        {
            "id": "assignment-101",
            "title": "Task A",
            "description": "Details",
            "assigned_to": user_id,
            "due_date": "2024-06-30",
            "status": "in_progress",
        }
    ]

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("server_mock:app", host="0.0.0.0", port=8000, reload=True)
