import pytest
from flask import Flask
from pydantic import BaseModel, ConfigDict
from apigateway.core.enums.validation_modes import ValidationMode
from apigateway.core.validation import validate_flask, PreValidators


def test_flask_json_validation():
    """Test Flask adapter with JSON payload"""
    app = Flask(__name__)
    
    class UserSchema(BaseModel):
        username: str
        age: int
        model_config = ConfigDict(extra="forbid")
    
    @app.route('/users', methods=['POST'])
    @validate_flask(UserSchema)
    def create_user(validated: UserSchema):
        return {
            "message": "User created", 
            "username": validated.username, 
            "age": validated.age
        }
    
    with app.test_client() as client:
        response = client.post('/users', json={"username": "alice", "age": 25})
        assert response.status_code == 200
        data = response.get_json()
        assert data["username"] == "alice"
        assert data["age"] == 25


def test_flask_form_data_validation():
    """Test Flask adapter with form data"""
    app = Flask(__name__)
    
    class ContactSchema(BaseModel):
        name: str
        email: str
        model_config = ConfigDict(extra="forbid")
    
    @app.route('/contact', methods=['POST'])
    @validate_flask(ContactSchema, mode=ValidationMode.LAX)
    def submit_contact(validated: ContactSchema):
        return {"name": validated.name, "email": validated.email}
    
    with app.test_client() as client:
        response = client.post('/contact', data={"name": "Bob", "email": "BOB@TEST.COM"})
        assert response.status_code == 200
        data = response.get_json()
        assert data["name"] == "Bob"
        assert data["email"] == "BOB@TEST.COM"


def test_flask_query_params_validation():
    """Test Flask adapter with query parameters"""
    app = Flask(__name__)
    
    class SearchSchema(BaseModel):
        query: str
        limit: int = 10
        model_config = ConfigDict(extra="forbid")
    
    @app.route('/search', methods=['GET'])
    @validate_flask(SearchSchema, mode=ValidationMode.LAX)
    def search(validated: SearchSchema):
        return {"query": validated.query, "limit": validated.limit}
    
    with app.test_client() as client:
        response = client.get('/search?query=python&limit=5')
        assert response.status_code == 200
        data = response.get_json()
        assert data["query"] == "python"
        assert data["limit"] == 5


def test_flask_validation_error():
    """Test Flask adapter validation error handling"""
    app = Flask(__name__)
    
    class UserSchema(BaseModel):
        username: str
        age: int
        model_config = ConfigDict(extra="forbid")
    
    @app.route('/users', methods=['POST'])
    @validate_flask(UserSchema)
    def create_user(validated: UserSchema):
        return {"message": "success"}
    
    with app.test_client() as client:
        response = client.post('/users', json={"username": "alice"})
        assert response.status_code == 422
        
        response = client.post('/users', json={"username": "alice", "age": 25, "extra": "no"})
        assert response.status_code == 422
        
        response = client.post('/users', data='{"invalid": json}', content_type='application/json')
        assert response.status_code == 422


def test_flask_mixed_data_sources():
    """Test Flask adapter combining JSON body with query params"""
    app = Flask(__name__)
    
    class MixedSchema(BaseModel):
        name: str
        filter: str
        model_config = ConfigDict(extra="forbid")
    
    @app.route('/mixed', methods=['POST'])
    @validate_flask(MixedSchema, mode=ValidationMode.LAX)
    def mixed_endpoint(validated: MixedSchema):
        return {"name": validated.name, "filter": validated.filter}
    
    with app.test_client() as client:
        response = client.post('/mixed?filter=active', json={"name": "test"})
        assert response.status_code == 200
        data = response.get_json()
        assert data["name"] == "test"
        assert data["filter"] == "active"


# -------------------
# Pre/Post Validators
# -------------------

def test_flask_pre_validators_normalize_email_and_sanitize():
    """Test that pre-validators modify request data before validation"""
    app = Flask(__name__)
    
    class ContactSchema(BaseModel):
        email: str
        name: str
        model_config = ConfigDict(extra="forbid")
    
    @app.route('/contact', methods=['POST'])
    @validate_flask(
        ContactSchema,
        mode=ValidationMode.LAX,
        pre_validators=[PreValidators.normalize_email, PreValidators.sanitize_strings]
    )
    def submit_contact(validated: ContactSchema):
        return {"email": validated.email, "name": validated.name}
    
    with app.test_client() as client:
        response = client.post('/contact', json={"email": "   TEST@Email.Com  ", "name": "   Alice   "})
        assert response.status_code == 200
        data = response.get_json()
        assert data["email"] == "test@email.com"  # normalized + lowercased
        assert data["name"] == "Alice"           # whitespace stripped


def test_flask_post_validators():
    """Test that post-validators transform validated model"""
    app = Flask(__name__)
    
    class UserSchema(BaseModel):
        username: str
        model_config = ConfigDict(extra="forbid")
    
    def uppercase_username(user: UserSchema) -> UserSchema:
        user.username = user.username.upper()
        return user
    
    @app.route('/users', methods=['POST'])
    @validate_flask(UserSchema, post_validators=[uppercase_username])
    def create_user(validated: UserSchema):
        return {"username": validated.username}
    
    with app.test_client() as client:
        response = client.post('/users', json={"username": "charlie"})
        assert response.status_code == 200
        data = response.get_json()
        assert data["username"] == "CHARLIE"  # post-validator applied
