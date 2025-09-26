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
from flask_cors import CORS
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
CORS(app)

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

class ComprehensiveSchema(BaseModel):
    # Required fields
    username: str
    email: str
    age: int
    
    # Optional fields with defaults
    full_name: Optional[str] = None
    phone: Optional[str] = None
    bio: Optional[str] = None
    
    # Nested object
    address: Optional[Dict[str, Any]] = None
    
    # Arrays
    skills: List[str] = []
    interests: List[str] = []
    
    # Enum-like constrained values
    role: str = "user"  # Will validate against allowed values in post-validator
    status: str = "active"
    
    # Numbers with validation
    salary: Optional[int] = None
    experience_years: int = 0
    
    # Booleans
    is_verified: bool = False
    accepts_marketing: bool = False
    
    # Date/time as string (would be validated in post-validator)
    birth_date: Optional[str] = None
    
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
def validate_comprehensive_data(data: Dict[str, Any]) -> Dict[str, Any]:
    """Pre-validator: Clean and validate comprehensive data"""
    # Email normalization
    if 'email' in data and isinstance(data['email'], str):
        data['email'] = data['email'].lower().strip()
    
    # Phone number cleaning
    if 'phone' in data and data['phone']:
        data['phone'] = ''.join(char for char in str(data['phone']) if char.isdigit() or char in ['+', '-', ' ', '(', ')'])
    
    # Skills/interests cleaning
    for field in ['skills', 'interests']:
        if field in data and isinstance(data[field], list):
            data[field] = [item.strip() for item in data[field] if item and item.strip()]
    
    return data

def enforce_business_rules(validated: ComprehensiveSchema) -> ComprehensiveSchema:
    """Post-validator: Enforce business rules and constraints"""
    errors = []
    
    # Email validation
    if not '@' in validated.email or not '.' in validated.email.split('@')[1]:
        errors.append("Invalid email format")
    
    # Age validation
    if validated.age < 13:
        errors.append("Age must be at least 13")
    elif validated.age > 120:
        errors.append("Age must be less than 120")
    
    # Role validation
    allowed_roles = ['user', 'admin', 'moderator', 'premium', 'guest']
    if validated.role not in allowed_roles:
        errors.append(f"Role must be one of: {', '.join(allowed_roles)}")
    
    # Status validation
    allowed_statuses = ['active', 'inactive', 'pending', 'suspended']
    if validated.status not in allowed_statuses:
        errors.append(f"Status must be one of: {', '.join(allowed_statuses)}")
    
    # Salary validation
    if validated.salary is not None:
        if validated.salary < 0:
            errors.append("Salary cannot be negative")
        elif validated.salary > 10000000:
            errors.append("Salary seems unrealistic (max: $10M)")
    
    # Experience validation
    if validated.experience_years < 0:
        errors.append("Experience years cannot be negative")
    elif validated.experience_years > validated.age - 10:
        errors.append("Experience years cannot exceed age minus 10")
    
    # Phone validation
    if validated.phone and len(validated.phone.replace(' ', '').replace('-', '').replace('(', '').replace(')', '')) < 10:
        errors.append("Phone number must be at least 10 digits")
    
    # Address validation
    if validated.address:
        required_address_fields = ['street', 'city', 'country']
        missing_fields = [field for field in required_address_fields if field not in validated.address or not validated.address[field]]
        if missing_fields:
            errors.append(f"Address missing required fields: {', '.join(missing_fields)}")
    
    # Skills validation
    if len(validated.skills) > 20:
        errors.append("Maximum 20 skills allowed")
    
    # Birth date validation (basic format check)
    if validated.birth_date:
        try:
            from datetime import datetime
            datetime.strptime(validated.birth_date, '%Y-%m-%d')
        except ValueError:
            errors.append("Birth date must be in YYYY-MM-DD format")
    
    if errors:
        raise ValueError("; ".join(errors))
    
    return validated

def log_comprehensive_submission(validated: ComprehensiveSchema) -> ComprehensiveSchema:
    """Post-validator: Log comprehensive data submission"""
    app_logger.log(LogLevel.INFO, "Comprehensive data submission", {
        'data_type': 'comprehensive_profile',
        'username': validated.username,
        'email_domain': validated.email.split('@')[1] if '@' in validated.email else 'unknown',
        'age_range': '18-25' if validated.age <= 25 else '26-40' if validated.age <= 40 else '40+',
        'role': validated.role,
        'status': validated.status,
        'has_address': validated.address is not None,
        'skills_count': len(validated.skills),
        'interests_count': len(validated.interests),
        'has_salary': validated.salary is not None,
        'is_verified': validated.is_verified
    })
    return validated

# Add this endpoint after the existing endpoints

@app.route('/comprehensive-demo', methods=['POST'])
@log_request_flask()
@rate_limit_flask(requests=5, window=60, scope="comprehensive")
@validate_flask(
    ComprehensiveSchema, 
    mode=ValidationMode.STRICT,
    pre_validators=[validate_comprehensive_data],
    post_validators=[enforce_business_rules, log_comprehensive_submission]
)
def comprehensive_validation_demo(validated: ComprehensiveSchema, _rate_limit_info=None):
    """Comprehensive validation demo endpoint - showcases extensive schema validation."""
    
    # Additional processing based on validated data
    profile_score = 0
    
    # Calculate profile completeness score
    if validated.full_name:
        profile_score += 10
    if validated.phone:
        profile_score += 10
    if validated.bio:
        profile_score += 15
    if validated.address:
        profile_score += 20
    if validated.skills:
        profile_score += 15
    if validated.interests:
        profile_score += 10
    if validated.salary is not None:
        profile_score += 10
    if validated.birth_date:
        profile_score += 10
    
    # Base score for required fields
    profile_score += 20
    
    # Determine profile tier
    if profile_score >= 80:
        tier = "premium"
    elif profile_score >= 60:
        tier = "standard"
    else:
        tier = "basic"
    
    app_logger.log(LogLevel.INFO, "Profile processing completed", {
        'processing_result': 'success',
        'profile_score': profile_score,
        'profile_tier': tier,
        'username': validated.username
    })
    
    return jsonify({
        "success": True,
        "message": "Comprehensive data validation successful!",
        "profile": {
            "username": validated.username,
            "email": validated.email,
            "age": validated.age,
            "full_name": validated.full_name,
            "role": validated.role,
            "status": validated.status,
            "is_verified": validated.is_verified,
            "skills_count": len(validated.skills),
            "interests_count": len(validated.interests),
            "has_address": validated.address is not None,
            "has_salary": validated.salary is not None
        },
        "analysis": {
            "profile_completeness_score": profile_score,
            "profile_tier": tier,
            "validation_stages_passed": [
                "schema_validation",
                "pre_validation_cleanup", 
                "business_rules_validation",
                "logging_and_audit"
            ]
        },
        "processed_at": datetime.now().isoformat()
    })

@app.route('/validation-examples', methods=['GET'])
@log_request_flask()
def get_validation_examples():
    """Get examples of valid and invalid data for testing."""
    return jsonify({
        "valid_example": {
            "username": "johndoe123",
            "email": "john.doe@company.com",
            "age": 28,
            "full_name": "John Doe",
            "phone": "+1-555-123-4567",
            "bio": "Software engineer with 5 years of experience",
            "address": {
                "street": "123 Main St",
                "city": "San Francisco",
                "state": "CA",
                "country": "USA",
                "zip": "94105"
            },
            "skills": ["Python", "JavaScript", "React", "SQL"],
            "interests": ["Technology", "Reading", "Hiking"],
            "role": "user",
            "status": "active",
            "salary": 95000,
            "experience_years": 5,
            "is_verified": True,
            "accepts_marketing": False,
            "birth_date": "1995-03-15"
        },
        "invalid_examples": {
            "missing_required_fields": {
                "username": "test",
                # Missing email and age
                "role": "user"
            },
            "invalid_email": {
                "username": "testuser",
                "email": "not-an-email",
                "age": 25
            },
            "invalid_age": {
                "username": "testuser", 
                "email": "test@example.com",
                "age": 5  # Too young
            },
            "invalid_role": {
                "username": "testuser",
                "email": "test@example.com", 
                "age": 25,
                "role": "invalid_role"  # Not in allowed list
            },
            "experience_age_mismatch": {
                "username": "testuser",
                "email": "test@example.com",
                "age": 22,
                "experience_years": 20  # More experience than possible
            },
            "extra_fields_forbidden": {
                "username": "testuser",
                "email": "test@example.com",
                "age": 25,
                "forbidden_field": "this will cause error",
                "another_extra": "also not allowed"
            },
            "invalid_address": {
                "username": "testuser",
                "email": "test@example.com",
                "age": 25,
                "address": {
                    "street": "123 Main St"
                    # Missing required city and country
                }
            },
            "too_many_skills": {
                "username": "testuser",
                "email": "test@example.com",
                "age": 25,
                "skills": [f"Skill {i}" for i in range(25)]  # More than 20
            }
        },
        "testing_tips": [
            "Try the valid example first to see successful validation",
            "Then try each invalid example to see specific error messages",
            "Mix and match errors to see multiple validation failures",
            "Check the logs to see pre/post validator activity",
            "Notice how pre-validators clean data before validation",
            "See how post-validators enforce business rules"
        ]
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
# SIMPLE VALIDATION DEMO - 4 FIELDS WITH COMPREHENSIVE VALIDATION
# =============================================================================

class SimpleProfileSchema(BaseModel):
    username: str
    email: str
    age: int
    department: str
    model_config = ConfigDict(extra='forbid')

def clean_profile_data(data: Dict[str, Any]) -> Dict[str, Any]:
    """Pre-validator: Clean and normalize profile data"""
    # Email normalization
    if 'email' in data and isinstance(data['email'], str):
        data['email'] = data['email'].lower().strip()
    
    # Department normalization
    if 'department' in data and isinstance(data['department'], str):
        data['department'] = data['department'].strip().title()
    
    # Username cleaning
    if 'username' in data and isinstance(data['username'], str):
        data['username'] = data['username'].strip().lower()
    
    return data

def validate_business_rules(validated: SimpleProfileSchema) -> SimpleProfileSchema:
    """Post-validator: Enforce business rules"""
    errors = []
    
    # Username validation
    if len(validated.username) < 3:
        errors.append("Username must be at least 3 characters")
    if not validated.username.isalnum():
        errors.append("Username must contain only letters and numbers")
    
    # Email validation
    if not '@' in validated.email or not '.' in validated.email.split('@')[1]:
        errors.append("Invalid email format")
    if not validated.email.endswith('@company.com'):
        errors.append("Email must be from company domain (@company.com)")
    
    # Age validation
    if validated.age < 18:
        errors.append("Age must be at least 18")
    elif validated.age > 65:
        errors.append("Age must be less than 65")
    
    # Department validation
    allowed_departments = ['Engineering', 'Marketing', 'Sales', 'Hr', 'Finance']
    if validated.department not in allowed_departments:
        errors.append(f"Department must be one of: {', '.join(allowed_departments)}")
    
    if errors:
        raise ValueError("; ".join(errors))
    
    return validated

def log_profile_creation(validated: SimpleProfileSchema) -> SimpleProfileSchema:
    """Post-validator: Log profile creation for audit"""
    app_logger.log(LogLevel.INFO, "Profile validation completed", {
        'validation_type': 'simple_profile',
        'username': validated.username,
        'email_domain': validated.email.split('@')[1],
        'department': validated.department,
        'age_range': '18-30' if validated.age <= 30 else '31-50' if validated.age <= 50 else '50+'
    })
    return validated

# =============================================================================
# VALIDATION DEMO ENDPOINTS - CONNECTS TO HTML FORM
# =============================================================================

@app.route('/profile-demo', methods=['POST'])
@log_request_flask()
@rate_limit_flask(requests=5, window=60, scope="profile_demo")
@validate_flask(
    SimpleProfileSchema, 
    mode=ValidationMode.STRICT,
    pre_validators=[clean_profile_data],
    post_validators=[validate_business_rules, log_profile_creation]
)
def profile_validation_demo(validated: SimpleProfileSchema, _rate_limit_info=None):
    """Simple profile validation demo - showcases comprehensive validation with just 4 fields."""
    
    # Calculate profile score based on validation rules passed
    profile_score = 50  # Base score for passing basic validation
    
    # Bonus points for good practices
    if len(validated.username) >= 5:
        profile_score += 10
    if validated.age >= 25:
        profile_score += 10
    if validated.department in ['Engineering', 'Marketing']:
        profile_score += 15
    if validated.email.count('.') >= 2:  # more professional email format
        profile_score += 15
    
    # Determine validation tier
    if profile_score >= 85:
        tier = "excellent"
    elif profile_score >= 70:
        tier = "good"
    else:
        tier = "basic"
    
    app_logger.log(LogLevel.INFO, "Profile validation demo completed", {
        'demo_result': 'success',
        'profile_score': profile_score,
        'validation_tier': tier,
        'username': validated.username,
        'department': validated.department
    })
    
    return jsonify({
        "success": True,
        "message": "Profile validation successful!",
        "profile": {
            "username": validated.username,
            "email": validated.email,
            "age": validated.age,
            "department": validated.department
        },
        "validation_analysis": {
            "score": profile_score,
            "tier": tier,
            "stages_passed": [
                "schema_validation",
                "pre_validation_cleanup", 
                "business_rules_validation",
                "audit_logging"
            ]
        },
        "processed_at": datetime.now().isoformat()
    })

@app.route('/profile-demo/examples', methods=['GET'])
@log_request_flask()
def get_profile_examples():
    """Get examples of valid and invalid profile data for testing."""
    return jsonify({
        "valid_example": {
            "username": "john123",
            "email": "john.doe@company.com",
            "age": 28,
            "department": "Engineering"
        },
        "invalid_examples": {
            "short_username": {
                "username": "jo",  # Too short
                "email": "jo@company.com",
                "age": 25,
                "department": "Engineering"
            },
            "wrong_email_domain": {
                "username": "testuser",
                "email": "test@gmail.com",  # Wrong domain
                "age": 25,
                "department": "Engineering"
            },
            "invalid_age": {
                "username": "testuser",
                "email": "test@company.com",
                "age": 16,  # Too young
                "department": "Engineering"
            },
            "invalid_department": {
                "username": "testuser",
                "email": "test@company.com",
                "age": 25,
                "department": "InvalidDept"  # Not in allowed list
            },
            "special_chars_username": {
                "username": "test@user!",  # Invalid characters
                "email": "test@company.com",
                "age": 25,
                "department": "Engineering"
            },
            "extra_fields": {
                "username": "testuser",
                "email": "test@company.com",
                "age": 25,
                "department": "Engineering",
                "extra_field": "not allowed"  # Extra field forbidden
            }
        },
        "allowed_departments": ["Engineering", "Marketing", "Sales", "Hr", "Finance"],
        "validation_rules": {
            "username": "3+ chars, alphanumeric only",
            "email": "Must be @company.com domain",
            "age": "Between 18-65",
            "department": "Must be from allowed list"
        }
    })
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