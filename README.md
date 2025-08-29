# API Gateway


**API Gateway** is a modular, developer-friendly Python project designed to become a **full-featured API Gateway framework**.  
Right now (v1.0.0) it ships with **request validation utilities** powered by [Pydantic](https://docs.pydantic.dev).  
In the coming weeks, it will expand into routing, authentication, rate limiting, logging, and more.

---

##  Vision
The goal of **API Gateway** is to provide:
-  **Validation**: Ensure only clean, schema-compliant data enters your services. *(available today)*  
-  **Authentication & Authorization**: Pluggable security layers. *(coming soon)*  
-  **Observability**: Metrics, logging, tracing. *(coming soon)*  
-  **Routing**: Intelligent request routing and proxying. *(coming soon)*  
-  **Rate Limiting & QoS**: Keep traffic fair and resilient. *(coming soon)*  
 

---

##  Installation For Contribution

To get started you need [`uv`](https://docs.astral.sh/uv/), a fast Python package manager. Install it first with:

```bash
# On Linux / macOS
curl -LsSf https://astral.sh/uv/install.sh | sh

# On Windows (PowerShell)
powershell -c "irm https://astral.sh/uv/install.ps1 | iex"


git clone https://github.com/PrabhbirJ/apigateway.git
cd apigateway
uv sync --extra dev

# Run tests
uv run pytest
```

---

##  Installation To Use in Your Project

To get started you need [`uv`](https://docs.astral.sh/uv/), a fast Python package manager. Install it first with:

```bash
# On Linux / macOS
curl -LsSf https://astral.sh/uv/install.sh | sh

# On Windows (PowerShell)
powershell -c "irm https://astral.sh/uv/install.ps1 | iex"

cd {Project_Directory}

uv init
uv add git+https://github.com/PrabhbirJ/apigateway.git

uv add flask django fastapi

```

---

##  Project Structure

```bash
apigateway/
├── CHANGELOG.md
├── LICENSE
├── README.md
├── pyproject.toml
├── src/
│   └── apigateway/
│       ├── core/
│       │   ├── __init__.py
│       │   ├── adapters/
│       │   │   ├── __init__.py
│       │   │   ├── base_adapter.py
│       │   │   ├── django.py
│       │   │   ├── fastapi.py
│       │   │   ├── flask.py
│       │   │   └── generic.py
│       │   ├── enums/
│       │   │   ├── __init__.py
│       │   │   └── validation_modes.py
│       │   ├── errors/
│       │   │   ├── __init__.py
│       │   │   └── formatters.py
│       │   └── validation.py
│       └── exceptions/
│           ├── __init__.py
│           └── GatewayValidationError.py
├── tests/
│   ├── __init__.py
│   ├── validation/
│   │   ├── __init__.py
│   │   ├── test_adapters/
│   │   │   ├── __init__.py
│   │   │   ├── conftest.py
│   │   │   ├── test_django.py
│   │   │   ├── test_fastapi.py
│   │   │   └── test_flask.py
│   │   └── test_generic/
│   │       ├── __init__.py
│   │       ├── test_error_handling.py
│   │       ├── test_pre_post_validators.py
│   │       └── test_strict_vs_lax.py
└── uv.lock

```
---

## Error Handling

All validation errors are raised as GatewayValidationError with this schema:
```bash
{
  "error": "Validation Failed",
  "code": "validation_error",
  "details": [
    {
      "field": "id",
      "message": "value is not a valid integer",
      "type": "type_error.integer"
    }
  ]
}
```
You can customize formatting by supplying your own error_formatter

---

##  Flask Example

```python
from flask import Flask
from pydantic import BaseModel, ConfigDict
from apigateway.core.enums.validation_modes import ValidationMode
from apigateway.core.validation import validate_flask, PreValidators

app = Flask(__name__)

# --- SCHEMAS ---

class UserSchema(BaseModel):
    username: str
    age: int
    email: str
    model_config = ConfigDict(extra="forbid")

class ContactSchema(BaseModel):
    name: str
    email: str
    message: str
    model_config = ConfigDict(extra="forbid")

class SearchSchema(BaseModel):
    query: str
    limit: int = 10
    category: str = "all"
    model_config = ConfigDict(extra="forbid")

# --- ENDPOINTS ---

@app.route('/users', methods=['POST'])
@validate_flask(UserSchema, mode=ValidationMode.STRICT)
def create_user(validated: UserSchema):
    """Create a new user - JSON body required"""
    return {
        "success": True,
        "message": f"User {validated.username} created successfully",
        "user": {
            "username": validated.username,
            "age": validated.age,
            "email": validated.email
        }
    }

@app.route('/contact', methods=['POST'])
@validate_flask(
    ContactSchema,
    mode=ValidationMode.LAX,
    pre_validators=[PreValidators.normalize_email, PreValidators.sanitize_strings]
)
def submit_contact(validated: ContactSchema):
    """Submit contact form - handles form data or JSON"""
    return {
        "success": True,
        "message": "Contact form submitted",
        "data": {
            "name": validated.name,
            "email": validated.email,
            "message": validated.message
        }
    }

@app.route('/search', methods=['GET'])
@validate_flask(SearchSchema, mode=ValidationMode.LAX)
def search(validated: SearchSchema):
    """Search with query parameters"""
    return {
        "success": True,
        "query": validated.query,
        "limit": validated.limit,
        "category": validated.category,
        "results": f"Found results for '{validated.query}' in {validated.category}"
    }

@app.route('/mixed', methods=['POST'])
@validate_flask(UserSchema, mode=ValidationMode.LAX)
def mixed_data(validated: UserSchema):
    """Combines JSON body + query parameters"""
    return {
        "success": True,
        "message": "Mixed data processed",
        "user": validated.dict()
    }

# Custom post-validator example
def uppercase_username(user: UserSchema) -> UserSchema:
    user.username = user.username.upper()
    return user

@app.route('/users/premium', methods=['POST'])
@validate_flask(UserSchema, post_validators=[uppercase_username])
def create_premium_user(validated: UserSchema):
    """Create premium user with uppercase username"""
    return {
        "success": True,
        "message": f"Premium user {validated.username} created",
        "user": validated.dict()
    }

@app.route('/', methods=['GET'])
def home():
    """API documentation"""
    return {
        "message": "API Gateway Flask Example",
        "endpoints": {
            "POST /users": "Create user (JSON: username, age, email)",
            "POST /contact": "Submit contact form (JSON/form: name, email, message)",
            "GET /search": "Search (query params: query, limit?, category?)",
            "POST /mixed": "Mixed data (JSON body + query params)",
            "POST /users/premium": "Create premium user (uppercase username)"
        },
        "test_examples": {
            "create_user": "curl -X POST http://localhost:5000/users -H 'Content-Type: application/json' -d '{\"username\":\"alice\",\"age\":25,\"email\":\"alice@example.com\"}'",
            "search": "curl 'http://localhost:5000/search?query=python&limit=5&category=tutorials'",
            "contact_form": "curl -X POST http://localhost:5000/contact -d 'name=Bob&email=BOB@TEST.COM&message=Hello world'",
            "mixed_data": "curl -X POST 'http://localhost:5000/mixed?age=30' -H 'Content-Type: application/json' -d '{\"username\":\"charlie\",\"email\":\"charlie@test.com\"}'"
        }
    }

if __name__ == '__main__':
    print("🚀 Starting Flask API Gateway Example...")
    print("📍 Open http://localhost:5000 for documentation and test commands")
    print("🔧 Try the curl commands shown in the response!")
    app.run(debug=True, host='0.0.0.0', port=5000)
```
