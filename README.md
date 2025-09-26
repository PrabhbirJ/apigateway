# API Gateway


**API Gateway** is a modular, developer-friendly Python project designed to become a **full-featured API Gateway framework**.  
(v1.4.0) it ships with **request validation utilities, authorization, rate limiting and logging** powered by [Pydantic](https://docs.pydantic.dev).  


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
uv sync --all-extras --dev

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
apigateway
├── CHANGELOG.md
├── LICENSE
├── README.md
├── pyproject.toml
├── src
│   ├── apigateway
│   │   ├── core
│   │   │   ├── __init__.py
│   │   │   ├── adapters
│   │   │   │   ├── __init__.py
│   │   │   │   ├── base_adapter.py
│   │   │   │   ├── django.py
│   │   │   │   ├── fastapi.py
│   │   │   │   ├── flask.py
│   │   │   │   └── generic.py
│   │   │   ├── auth
│   │   │   │   ├── __init__.py
│   │   │   │   └── auth.py
│   │   │   ├── enums
│   │   │   │   ├── __init__.py
│   │   │   │   └── validation_modes.py
│   │   │   ├── errors
│   │   │   │   ├── __init.py
│   │   │   │   └── formatters.py
│   │   │   └── validation
│   │   │       ├── __init__.py
│   │   │       ├── file_validation.py
│   │   │       └── validation.py
│   │   └── exceptions
│   │       ├── AuthError.py
│   │       ├── GatewayValidationError.py
│   │       ├── __init__.py
│   └── apigateway.egg-info
│       ├── PKG-INFO
│       ├── SOURCES.txt
│       ├── dependency_links.txt
│       ├── requires.txt
│       └── top_level.txt
├── tests
│   ├── __init__.py
│   └── validation
│       ├── __init__.py
│       ├── test_adapters
│       │   ├── __init__.py
│       │   ├── conftest.py
│       │   ├── test_django.py
│       │   ├── test_fastapi.py
│       │   └── test_flask.py
│       └── test_generic
│           ├── __init__.py
│           ├── test_error_handling.py
│           ├── test_pre_post_validators.py
│           └── test_strict_vs_lax.py
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
import os
import json
import base64
import time
import secrets
import jwt  # Add this import
from datetime import datetime, timedelta
from flask import Flask, jsonify, request
from pydantic import BaseModel, ConfigDict
from typing import Optional, List, Dict, Any

# API Gateway imports
from apigateway.core.validation.validation import validate_flask, PreValidators
from apigateway.core.enums.validation_modes import ValidationMode
from apigateway.core.auth.auth import authorize_flask  # Updated import
from apigateway.core.rate_limit.RateLimitEngine import configure_rate_limiting, KeyGenerators
from apigateway.core.rate_limit.RateLimiting import rate_limit_flask
from apigateway.core.rate_limit.MemoryBackend import MemoryBackend

# NEW: Logging system imports
from apigateway.core.logging import configure_logging, JsonLogger, LogLevel, get_logger
from apigateway.core.logging.logger import log_request_flask

# =============================================================================
# LOGGING CONFIGURATION
# =============================================================================

# Configure structured JSON logging
logger_instance = JsonLogger(
    log_level=LogLevel.INFO,
    enable_sampling=False,  # Disable sampling for demo (log everything)
    masked_fields={'authorization', 'cookie', 'x-api-key', 'token', 'password'}
)
configure_logging(logger_instance)

# Get logger for manual logging
app_logger = get_logger()

# =============================================================================
# APPLICATION SETUP
# =============================================================================

# Configure rate limiting with memory backend
configure_rate_limiting(MemoryBackend())

app = Flask(__name__)

# =============================================================================
# MOCK USER DATABASE
# =============================================================================

users_db = {
    "testuser": {
        "user_id": "1", 
        "username": "testuser",
        "email": "test@example.com",
        "roles": ["user", "admin"]
    },
    "user1": {
        "user_id": "2", 
        "username": "user1",
        "email": "user1@example.com",
        "roles": ["user"]
    },
    "premium": {
        "user_id": "3", 
        "username": "premium",
        "email": "premium@example.com",
        "roles": ["user", "premium"]
    },
    "moderator": {
        "user_id": "4", 
        "username": "moderator", 
        "email": "mod@example.com",
        "roles": ["user", "moderator"]
    }
}

# JWT secret for proper token signing
JWT_SECRET_KEY = "demo-secret-key-32-characters-long-for-development-only!"
JWT_ALGORITHM = "HS256"

# =============================================================================
# JWT DECODER - PROGRAMMER'S RESPONSIBILITY
# =============================================================================

def my_jwt_decoder(token: str) -> Dict[str, Any]:
    """Our JWT decoder - we handle the secret and decoding logic."""
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        return {
            'user_id': payload.get('sub'),
            'username': payload.get('username'),
            'email': payload.get('email'),
            'roles': payload.get('roles', []),
            'permissions': payload.get('permissions', []),
            'token_payload': payload
        }
    except jwt.ExpiredSignatureError:
        raise Exception("Token has expired")
    except jwt.InvalidSignatureError:
        raise Exception("Invalid token signature")
    except jwt.InvalidTokenError as e:
        raise Exception(f"Invalid token: {str(e)}")

# =============================================================================
# SCHEMAS
# =============================================================================

class TokenRequestSchema(BaseModel):
    username: str
    model_config = ConfigDict(extra='forbid')

class ProtectedDataSchema(BaseModel):
    important_data: str
    sensitive_info: Optional[str] = None
    model_config = ConfigDict(extra='forbid')

class UserSchema(BaseModel):
    username: str
    age: int
    email: str
    model_config = ConfigDict(extra='forbid')

class ContactSchema(BaseModel):
    name: str
    email: str
    message: str
    model_config = ConfigDict(extra='ignore')

class SearchSchema(BaseModel):
    query: str
    limit: int = 10
    category: str = "all"
    model_config = ConfigDict(extra='forbid')

class PostSchema(BaseModel):
    title: str
    content: str
    tags: List[str] = []
    model_config = ConfigDict(extra='forbid')

class ApiKeySchema(BaseModel):
    name: str
    permissions: List[str]
    model_config = ConfigDict(extra='forbid')

# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def create_jwt_token(user_data: dict) -> str:
    """Create a properly signed JWT token."""
    now = int(time.time())
    payload = {
        "sub": str(user_data["user_id"]),
        "username": user_data["username"],
        "email": user_data["email"],
        "roles": user_data["roles"],
        "permissions": ["read", "write"],
        "iat": now,
        "exp": now + 3600,  # 1 hour
        "jti": f"token_{user_data['user_id']}_{now}"
    }
    
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)

def create_custom_role_token(roles: List[str], username: str = "demo_user") -> str:
    """Create JWT token with custom roles."""
    user_data = {
        "user_id": f"demo_{int(time.time())}",
        "username": username,
        "email": f"{username}@demo.com",
        "roles": roles
    }
    return create_jwt_token(user_data)

# Post-validators with logging
def audit_user_creation(user: UserSchema) -> UserSchema:
    """Post-validator: Log user creation for audit."""
    app_logger.log(LogLevel.INFO, "User creation audit", {
        'audit_action': 'user_creation',
        'new_username': user.username,
        'user_age': user.age,
        'user_email': user.email
    })
    return user

def uppercase_username(user: UserSchema) -> UserSchema:
    """Post-validator: Transform username to uppercase."""
    original_username = user.username
    user.username = user.username.upper()
    
    app_logger.log(LogLevel.INFO, "Username transformed", {
        'transformation': 'uppercase',
        'original_username': original_username,
        'new_username': user.username
    })
    return user

def validate_admin_email(user: UserSchema) -> UserSchema:
    """Post-validator: Ensure admin users have company email."""
    if "@company.com" not in user.email:
        app_logger.log(LogLevel.WARNING, "Admin email validation failed", {
            'validation_rule': 'company_email_required',
            'provided_email': user.email,
            'username': user.username
        })
        raise ValueError("Admin users must have @company.com email address")
    
    app_logger.log(LogLevel.INFO, "Admin email validation passed", {
        'validation_rule': 'company_email_required',
        'email': user.email,
        'username': user.username
    })
    return user

# =============================================================================
# ROUTES WITH COMPREHENSIVE LOGGING
# =============================================================================

@app.route('/', methods=['GET'])
@log_request_flask()  # Log all requests to home page
def home():
    """API documentation showing all available endpoints."""
    app_logger.log(LogLevel.INFO, "API documentation requested", {
        'endpoint': 'home',
        'documentation_type': 'api_overview'
    })
    
    return jsonify({
        "message": "API Gateway Demo - JWT + Logging",
        "version": "3.0-LOGGING",
        "features": ["JWT Verification", "Validation", "RBAC", "Rate Limiting", "Structured Logging"],
        "logging": {
            "format": "structured_json",
            "correlation_tracking": "enabled",
            "sensitive_masking": "enabled",
            "log_level": "INFO"
        },
        "endpoints": {
            "token_generation": {
                "POST /get-token": "Get JWT token (rate limited: 10/min)",
                "GET /whoami": "Get current user info (requires valid JWT)"
            },
            "public": {
                "POST /contact": "Submit contact form (rate limited: 10/min)",
                "GET /search": "Search with query params (rate limited: 20/min)",
                "GET /public-data": "Get public data (rate limited: 100/min)"
            },
            "user_protected": {
                "GET /profile": "View profile (user role required)",
                "POST /posts": "Create post (user role + validation + rate limit: 5/min)",
                "POST /submit": "Submit protected data (user role + validation)"
            },
            "admin_only": {
                "POST /users": "Create user (admin role + rate limit: 2/min)",
                "POST /admin/users": "Create admin user (admin role + strict validation)",
                "GET /admin/stats": "View admin stats (admin role)"
            },
            "moderator_only": {
                "POST /moderate": "Moderate content (moderator role + rate limit: 10/min)"
            },
            "premium_features": {
                "GET /premium/data": "Premium data access (premium role)",
                "POST /premium/api-keys": "Create API keys (premium role + rate limit: 1/min)"
            }
        }
    })

# =============================================================================
# TOKEN GENERATION WITH LOGGING
# =============================================================================

@app.route("/get-token", methods=["POST"])
@log_request_flask()                           # OUTERMOST - logs everything
@rate_limit_flask(requests=10, window=60)     # Rate limiting
@validate_flask(TokenRequestSchema)          # Validation
def get_token(validated: TokenRequestSchema, _rate_limit_info=None):
    """Generate JWT token for testing."""
    user = users_db.get(validated.username)
    if not user:
        app_logger.log(LogLevel.WARNING, "Token request for unknown user", {
            'requested_username': validated.username,
            'available_users': list(users_db.keys())
        })
        return jsonify({"error": "User not found"}), 404
    
    # Create properly signed JWT token
    access_token = create_jwt_token(user)
    
    app_logger.log(LogLevel.INFO, "JWT token generated successfully", {
        'token_action': 'generation',
        'username': user["username"],
        'user_id': user["user_id"],
        'roles': user["roles"],
        'token_expiry': datetime.fromtimestamp(int(time.time()) + 3600).isoformat()
    })
    
    return jsonify({
        "access_token": access_token,
        "token_type": "bearer",
        "expires_in": 3600,
        "user": {
            "username": user["username"],
            "roles": user["roles"]
        },
        "note": "Properly signed JWT token with verification"
    })

@app.route("/get-custom-token/<role>", methods=["GET"])
@log_request_flask()
@rate_limit_flask(requests=5, window=60, scope="custom_token")
def get_custom_token(role, _rate_limit_info=None):
    """Generate JWT token with specific role for testing."""
    valid_roles = ["user", "admin", "moderator", "premium"]
    
    if role not in valid_roles:
        app_logger.log(LogLevel.WARNING, "Invalid role requested for custom token", {
            'requested_role': role,
            'valid_roles': valid_roles
        })
        return jsonify({"error": f"Invalid role. Valid roles: {valid_roles}"}), 400
    
    token = create_custom_role_token([role], f"demo_{role}")
    
    app_logger.log(LogLevel.INFO, "Custom role token generated", {
        'token_action': 'custom_generation',
        'role': role,
        'demo_user': f"demo_{role}"
    })
    
    return jsonify({
        "access_token": token,
        "role": role,
        "expires_in": 3600,
        "note": f"JWT token with {role} role"
    })

@app.route("/whoami", methods=["GET"])
@log_request_flask()
@authorize_flask(token_decoder=my_jwt_decoder)  # FIXED - use token_decoder
def whoami(user):
    """Get current user information from verified JWT token."""
    app_logger.log(LogLevel.INFO, "User identity verified", {
        'identity_check': 'whoami',
        'user_id': user['user_id'],
        'username': user.get('username'),
        'roles': user['roles'],
        'token_id': user['token_payload'].get('jti')
    })
    
    return jsonify({
        "message": "JWT token successfully verified",
        "user": {
            "user_id": user["user_id"],
            "username": user.get("username"),
            "email": user.get("email"),
            "roles": user["roles"],
            "permissions": user.get("permissions", [])
        },
        "token_info": {
            "expires_at": datetime.fromtimestamp(user["token_payload"]["exp"]).isoformat(),
            "issued_at": datetime.fromtimestamp(user["token_payload"]["iat"]).isoformat(),
            "token_id": user["token_payload"].get("jti")
        }
    })

# =============================================================================
# PUBLIC ENDPOINTS WITH LOGGING
# =============================================================================

@app.route('/contact', methods=['POST'])
@log_request_flask()
@rate_limit_flask(requests=10, window=60, scope="contact")
@validate_flask(
    ContactSchema, 
    mode=ValidationMode.PERMISSIVE,
    pre_validators=[PreValidators.normalize_email, PreValidators.sanitize_strings]
)
def submit_contact(validated: ContactSchema, _rate_limit_info=None):
    """Submit contact form - public endpoint."""
    app_logger.log(LogLevel.INFO, "Contact form submitted", {
        'form_submission': 'contact',
        'contact_name': validated.name,
        'contact_email': validated.email,
        'message_length': len(validated.message)
    })
    
    return jsonify({
        "success": True,
        "message": "Contact form submitted successfully",
        "data": validated.model_dump()
    })

@app.route('/search', methods=['GET'])
@log_request_flask()
@rate_limit_flask(requests=20, window=60, scope="search")
@validate_flask(SearchSchema, mode=ValidationMode.LAX)
def search(validated: SearchSchema, _rate_limit_info=None):
    """Search endpoint with query parameters."""
    results = [
        f"Result {i} for '{validated.query}'" 
        for i in range(1, min(validated.limit + 1, 6))
    ]
    
    app_logger.log(LogLevel.INFO, "Search performed", {
        'search_action': 'query_executed',
        'query': validated.query,
        'category': validated.category,
        'limit': validated.limit,
        'results_count': len(results)
    })
    
    return jsonify({
        "query": validated.query,
        "category": validated.category,
        "results": results,
        "total": len(results)
    })

# =============================================================================
# USER PROTECTED ENDPOINTS WITH LOGGING
# =============================================================================

@app.route("/profile", methods=["GET"])
@log_request_flask()
@authorize_flask(["user"], token_decoder=my_jwt_decoder)  # FIXED - use token_decoder
def get_profile(user):
    """Get user profile - requires user role."""
    app_logger.log(LogLevel.INFO, "User profile accessed", {
        'profile_access': 'view',
        'user_id': user['user_id'],
        'username': user.get('username'),
        'account_type': "premium" if "premium" in user["roles"] else "standard"
    })
    
    return jsonify({
        "profile": {
            "user_id": user["user_id"],
            "username": user.get("username"),
            "email": user.get("email"),
            "roles": user["roles"],
            "account_type": "premium" if "premium" in user["roles"] else "standard"
        }
    })

@app.route('/posts', methods=['POST'])
@log_request_flask()                          # OUTERMOST - sees everything
@rate_limit_flask(requests=5, window=60, key_func=KeyGenerators.user_based)
@authorize_flask(["user"], token_decoder=my_jwt_decoder)  # FIXED - use token_decoder
@validate_flask(PostSchema)
def create_post(validated: PostSchema, user, _rate_limit_info=None):
    """Create a post - full decorator stack with logging."""
    post_id = int(time.time())
    
    app_logger.log(LogLevel.INFO, "Post created successfully", {
        'content_creation': 'post',
        'post_id': post_id,
        'title': validated.title,
        'content_length': len(validated.content),
        'tags_count': len(validated.tags),
        'author_id': user['user_id'],
        'author_username': user.get('username')
    })
    
    return jsonify({
        "success": True,
        "message": "Post created successfully",
        "post": {
            "id": post_id,
            "title": validated.title,
            "content": validated.content,
            "tags": validated.tags,
            "author": user.get("username"),
            "created_at": datetime.now().isoformat()
        }
    })

# =============================================================================
# ADMIN ENDPOINTS WITH COMPREHENSIVE LOGGING
# =============================================================================

@app.route('/users', methods=['POST'])
@log_request_flask()
@rate_limit_flask(requests=2, window=60, key_func=KeyGenerators.user_based)
@authorize_flask(["admin"], token_decoder=my_jwt_decoder)  # FIXED - use token_decoder
@validate_flask(UserSchema, mode=ValidationMode.STRICT, post_validators=[audit_user_creation])
def create_user(validated: UserSchema, user, _rate_limit_info=None):
    """Create a new user - admin only with comprehensive logging."""
    new_user_id = str(len(users_db) + 1)
    
    app_logger.log(LogLevel.INFO, "Admin user creation completed", {
        'admin_action': 'user_creation',
        'new_user_id': new_user_id,
        'new_username': validated.username,
        'new_user_email': validated.email,
        'created_by_admin_id': user['user_id'],
        'created_by_admin_username': user.get('username')
    })
    
    return jsonify({
        "success": True,
        "message": f"User {validated.username} created successfully",
        "user": {
            "id": new_user_id,
            **validated.model_dump()
        },
        "created_by": user.get("username")
    })

@app.route('/admin/users', methods=['POST'])
@log_request_flask()
@authorize_flask(["admin"], token_decoder=my_jwt_decoder)  # FIXED - use token_decoder
@validate_flask(
    UserSchema, 
    mode=ValidationMode.STRICT,
    post_validators=[validate_admin_email, uppercase_username, audit_user_creation]
)
def create_admin_user(validated: UserSchema, user):
    """Create admin user with multiple post-validators and logging."""
    app_logger.log(LogLevel.INFO, "Admin user creation with enhanced validation", {
        'admin_action': 'admin_user_creation',
        'new_admin_username': validated.username,
        'email_validated': True,
        'username_transformed': True,
        'created_by': user.get('username')
    })
    
    return jsonify({
        "success": True,
        "message": f"Admin user {validated.username} created",
        "user": validated.model_dump(),
        "created_by": user.get("username")
    })

@app.route('/admin/stats', methods=['GET'])
@log_request_flask()
@authorize_flask(["admin"], token_decoder=my_jwt_decoder)  # FIXED - use token_decoder
def admin_stats(user):
    """Get admin statistics."""
    stats_data = {
        "total_users": len(users_db),
        "admin_users": len([u for u in users_db.values() if "admin" in u["roles"]]),
        "premium_users": len([u for u in users_db.values() if "premium" in u["roles"]]),
        "server_uptime": "demo mode",
        "last_access": datetime.now().isoformat()
    }
    
    app_logger.log(LogLevel.INFO, "Admin statistics accessed", {
        'admin_action': 'stats_view',
        'accessed_by': user.get('username'),
        'stats_summary': {
            'total_users': stats_data["total_users"],
            'admin_users': stats_data["admin_users"],
            'premium_users': stats_data["premium_users"]
        }
    })
    
    return jsonify({
        "stats": stats_data,
        "accessed_by": user.get("username")
    })

# =============================================================================
# PREMIUM FEATURES WITH LOGGING
# =============================================================================

@app.route('/premium/data', methods=['GET'])
@log_request_flask()
@authorize_flask(["premium", "admin"], token_decoder=my_jwt_decoder)  # FIXED - use token_decoder
def get_premium_data(user):
    """Get premium data - premium role required."""
    app_logger.log(LogLevel.INFO, "Premium content accessed", {
        'premium_access': 'data_retrieval',
        'user_id': user['user_id'],
        'username': user.get('username'),
        'access_tier': 'premium'
    })
    
    return jsonify({
        "premium_data": {
            "exclusive_content": "This is premium content",
            "analytics": {"views": 12345, "engagement": "high"},
            "api_calls_remaining": 9999,
            "subscription_tier": "premium"
        },
        "user": user.get("username")
    })

@app.route('/premium/api-keys', methods=['POST'])
@log_request_flask()
@rate_limit_flask(requests=1, window=60, key_func=KeyGenerators.user_based)
@authorize_flask(["premium", "admin"], token_decoder=my_jwt_decoder)  # FIXED - use token_decoder
@validate_flask(ApiKeySchema)
def create_api_key(validated: ApiKeySchema, user, _rate_limit_info=None):
    """Create API key - premium feature with strict rate limiting."""
    api_key = f"ak_{secrets.token_urlsafe(32)}"
    
    app_logger.log(LogLevel.INFO, "API key created", {
        'api_key_action': 'creation',
        'key_name': validated.name,
        'permissions': validated.permissions,
        'created_by_user_id': user['user_id'],
        'created_by_username': user.get('username'),
        'key_prefix': api_key[:8] + "..."  # Log only prefix for security
    })
    
    return jsonify({
        "success": True,
        "api_key": {
            "key": api_key,
            "name": validated.name,
            "permissions": validated.permissions,
            "created_at": datetime.now().isoformat(),
            "expires_at": (datetime.now() + timedelta(days=365)).isoformat()
        },
        "owner": user.get("username")
    })

# =============================================================================
# ERROR HANDLERS WITH LOGGING
# =============================================================================

@app.errorhandler(404)
def not_found(error):
    app_logger.log(LogLevel.WARNING, "Endpoint not found", {
        'error_type': '404_not_found',
        'requested_path': request.path,
        'method': request.method
    })
    return jsonify({"error": "Endpoint not found"}), 404

@app.errorhandler(500)
def internal_error(error):
    app_logger.log(LogLevel.ERROR, "Internal server error occurred", {
        'error_type': '500_internal_error',
        'error_message': str(error),
        'path': request.path,
        'method': request.method
    })
    return jsonify({"error": "Internal server error"}), 500

# =============================================================================
# SERVER START
# =============================================================================

if __name__ == '__main__':
    print("🚀 Starting API Gateway with Comprehensive Logging...")
    print("🌐 Server: http://127.0.0.1:5001")
    print("📖 API Docs: GET http://127.0.0.1:5001/")
    
    print("\n📊 Logging Configuration:")
    print("  • Format: Structured JSON")
    print("  • Level: INFO")
    print("  • Correlation IDs: Enabled") 
    print("  • Sensitive Masking: Enabled")
    print("  • Sampling: Disabled (logs everything)")
    
    print("\n🔑 Demo Users (use POST /get-token):")
    for username, data in users_db.items():
        print(f"  • {username} (roles: {', '.join(data['roles'])})")
    
    print("\n🎭 Quick Test Tokens:")
    print("  • GET /get-custom-token/user")
    print("  • GET /get-custom-token/admin") 
    print("  • GET /get-custom-token/premium")
    print("  • GET /get-custom-token/moderator")
    
    app_logger.log(LogLevel.INFO, "Flask server starting", {
        'server_startup': True,
        'host': '127.0.0.1',
        'port': 5001,
        'environment': 'development',
        'logging_enabled': True,
        'jwt_verification': True
    })
    
    app.run(debug=True, host='127.0.0.1', port=5001)
```
