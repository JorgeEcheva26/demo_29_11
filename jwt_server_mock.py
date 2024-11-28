from fastapi import FastAPI, HTTPException, Depends, Path, Body
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from typing import List, Optional
from jose import JWTError, jwt
from datetime import datetime, timedelta

# Mock settings
SECRET_KEY = "your_secret_key"  # Replace with a secure key
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# OAuth2 configuration
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/token")

app = FastAPI(
    title="Southbound API",
    description="API to manage resources with JWT authentication.",
    version="1.0.0",
)

# Mock user database
USER_DB = {
    "admin": "password123",  # Replace with secure storage
}

# Token creation function
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# Authentication function
def authenticate_user(username: str, password: str):
    if username in USER_DB and USER_DB[username] == password:
        return username
    return None

# Dependency to verify the token
def verify_token(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None or username not in USER_DB:
            raise HTTPException(
                status_code=401,
                detail="Invalid token",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return username
    except JWTError:
        raise HTTPException(
            status_code=401,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        )

# Token endpoint
@app.post("/token", summary="Generate a JWT token", tags=["Authentication"])
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    username = authenticate_user(form_data.username, form_data.password)
    if not username:
        raise HTTPException(
            status_code=401,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

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

# Endpoints
@app.get("/v1/resources", response_model=List[Resource], tags=["Resources"])
def get_resources(username: str = Depends(verify_token)):
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

@app.post("/v1/resources", response_model=Resource, status_code=201, tags=["Resources"])
def create_resource(resource: NewResource, username: str = Depends(verify_token)):
    return {"id": "resource-456", **resource.dict()}

@app.get("/v1/resources/{resource_id}", response_model=Resource, tags=["Resources"])
def get_resource_details(
    resource_id: str = Path(..., description="ID of the resource"),
    username: str = Depends(verify_token)
):
    return {
        "id": resource_id,
        "name": "Resource 1",
        "description": "Details",
        "start_date": "2024-01-01",
        "end_date": "2024-12-31",
        "status": "active",
    }

@app.post("/v1/resources/tasks", response_model=Task, status_code=201, tags=["Tasks"])
def create_task(task: NewTask, username: str = Depends(verify_token)):
    return {"id": "task-789", **task.dict(), "status": "pending"}

@app.get("/v1/resources/users/{user_id}/information", response_model=List[Task], tags=["Tasks"])
def get_user_information(
    user_id: str = Path(..., description="User ID"),
    username: str = Depends(verify_token)
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

from fastapi.openapi.utils import get_openapi

def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    openapi_schema = get_openapi(
        title="Southbound API",
        version="1.0.0",
        description="API to manage resources with JWT authentication.",
        routes=app.routes,
    )
    openapi_schema["components"]["securitySchemes"] = {
        "BearerAuth": {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "JWT",
        }
    }
    for path in openapi_schema["paths"].values():
        for method in path.values():
            method["security"] = [{"BearerAuth": []}]
    app.openapi_schema = openapi_schema
    return openapi_schema

app.openapi = custom_openapi
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("jwt_server_mock:app", host="0.0.0.0", port=8000, reload=True)
