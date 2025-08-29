import asyncio
import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from pydantic import BaseModel, ConfigDict
from apigateway.core.validation import validate_fastapi
from apigateway.core.enums.validation_modes import ValidationMode


class UserSchema(BaseModel):
    username: str
    age: int = 25
    model_config = ConfigDict(extra="forbid")


class ContactSchema(BaseModel):
    name: str
    email: str
    model_config = ConfigDict(extra="ignore")  # For PERMISSIVE testing


class SearchSchema(BaseModel):
    query: str
    limit: int = 10
    model_config = ConfigDict(extra="forbid")


@pytest.mark.asyncio
async def test_fastapi_prevalidated_mode():
    """Test when FastAPI pre-validates (hybrid mode with existing model)"""
    app = FastAPI()
    
    @app.post("/users/")
    @validate_fastapi(UserSchema)
    async def create_user(user: UserSchema):  # FastAPI validates this
        return {"username": user.username, "age": user.age, "mode": "prevalidated"}
    
    client = TestClient(app)
    response = client.post("/users/", json={"username": "alice", "age": 30})
    
    assert response.status_code == 200
    data = response.json()
    assert data["username"] == "alice"
    assert data["age"] == 30
    assert data["mode"] == "prevalidated"



@pytest.mark.asyncio  
async def test_fastapi_post_validators():
    """Test post-validators work in both modes"""
    
    def audit_user(user: UserSchema) -> UserSchema:
        # Simulate audit logging
        user.username = f"audited_{user.username}"
        return user
    
    def uppercase_username(user: UserSchema) -> UserSchema:
        user.username = user.username.upper()
        return user
    
    app = FastAPI()
    
    @app.post("/users/")
    @validate_fastapi(UserSchema, post_validators=[audit_user, uppercase_username])
    async def create_user(user: UserSchema):
        return {"username": user.username, "age": user.age}
    
    client = TestClient(app)
    response = client.post("/users/", json={"username": "charlie", "age": 28})
    
    assert response.status_code == 200
    data = response.json()
    assert data["username"] == "AUDITED_CHARLIE"  # Both post-validators applied
    assert data["age"] == 28




@pytest.mark.asyncio
async def test_fastapi_error_handling():
    """Test FastAPI's validation errors (not decorator errors)"""
    app = FastAPI()
    
    class StrictUserSchema(BaseModel):
        username: str
        age: int  # No default - required field
        model_config = ConfigDict(extra="forbid")
    
    @app.post("/users/")
    @validate_fastapi(StrictUserSchema)
    async def create_user(user: StrictUserSchema):  # FastAPI handles validation
        return {"success": True}
    
    client = TestClient(app)
    
    # Missing required field (no default)
    response = client.post("/users/", json={"username": "alice"})
    assert response.status_code == 422  # FastAPI's error, not decorator's

@pytest.mark.asyncio
async def test_fastapi_mixed_parameters():
    """Test FastAPI functions with mixed parameter types"""
    app = FastAPI()
    
    @app.post("/users/{user_id}")
    @validate_fastapi(UserSchema)
    async def update_user(user_id: int, user: UserSchema):
        return {
            "user_id": user_id,
            "username": user.username, 
            "age": user.age,
            "operation": "update"
        }
    
    client = TestClient(app)
    response = client.post("/users/123", json={"username": "alice", "age": 30})
    
    assert response.status_code == 200
    data = response.json()
    assert data["user_id"] == 123
    assert data["username"] == "alice"
    assert data["operation"] == "update"





@pytest.mark.asyncio
async def test_fastapi_sync_function():
    """Test that sync functions also work"""
    app = FastAPI()
    
    @app.post("/users/")
    @validate_fastapi(UserSchema)
    def create_user_sync(validated: UserSchema):  # Sync function
        return {"username": validated.username, "sync": True}
    
    client = TestClient(app)
    response = client.post("/users/", json={"username": "sync_user", "age": 25})
    
    assert response.status_code == 200
    data = response.json()
    assert data["username"] == "sync_user"
    assert data["sync"] is True


