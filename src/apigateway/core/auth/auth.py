# core/auth.py
import inspect
import jwt
from functools import wraps
from typing import Callable, Dict, Any, List, Optional
from apigateway.core.adapters.base_adapter import FrameworkAdapter
from apigateway.core.adapters.django import DjangoAdapter
from apigateway.core.adapters.fastapi import FastAPIAdapter
from apigateway.core.adapters.flask import FlaskAdapter
from apigateway.core.adapters.generic import GenericAdapter
from apigateway.exceptions.AuthError import AuthError, AuthenticationError, AuthorizationError, TokenError


class JWTConfig:
    """JWT Configuration"""
    def __init__(self, 
                 secret: str,
                 algorithm: str = "HS256",
                 verify_exp: bool = True,
                 leeway: int = 10):
        self.secret = secret
        self.algorithm = algorithm
        self.verify_exp = verify_exp
        self.leeway = leeway


# Global JWT config - set this once in your app initialization
_jwt_config: Optional[JWTConfig] = None


def configure_jwt(secret: str, algorithm: str = "HS256", verify_exp: bool = True, leeway: int = 10):
    """Configure JWT settings globally"""
    global _jwt_config
    _jwt_config = JWTConfig(secret, algorithm, verify_exp, leeway)


def get_jwt_config() -> JWTConfig:
    """Get current JWT configuration"""
    if _jwt_config is None:
        raise RuntimeError(
            "JWT not configured. Call configure_jwt(secret='your-secret') before using auth decorators"
        )
    return _jwt_config


def authorize_request(
    required_roles: Optional[List[str]] = None,
    adapter: Optional[FrameworkAdapter] = None,
    jwt_config: Optional[JWTConfig] = None,
):
    """
    Framework-agnostic authorization decorator
    
    Args:
        required_roles: List of roles required to access this endpoint
        adapter: Framework adapter (if None, uses GenericAdapter)
        jwt_config: JWT configuration (if None, uses global config)
    
    Pipeline:
        extract_token → decode_jwt → extract_roles → check_roles → function
    """
    
    # Use GenericAdapter if no adapter specified
    if adapter is None:
        adapter = GenericAdapter()
    
    # Use global JWT config if none provided
    if jwt_config is None:
        jwt_config = get_jwt_config()
    
    # Default to empty list if no roles required (just check authentication)
    required_roles = required_roles or []
    
    def decorator(func: Callable):
        is_async = inspect.iscoroutinefunction(func)
        
        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            try:
                # Step 1: Extract JWT token from request
                token = adapter.extract_auth_token(*args, **kwargs)
                if not token:
                    raise AuthenticationError("No authentication token provided")
                
                # Step 2: Decode and validate JWT
                user_data = decode_jwt(token, jwt_config)
                
                # Step 3: Extract roles from JWT payload
                user_roles = user_data.get('roles', [])
                
                # Step 4: Check if user has required roles
                if required_roles and not has_required_roles(user_roles, required_roles):
                    raise AuthorizationError(
                        f"Access denied. Required roles: {required_roles}, User roles: {user_roles}"
                    )
                
                # Step 5: Inject user data into kwargs (similar to validation)
                if 'user' not in kwargs:
                    kwargs['user'] = user_data
                
                return await func(*args, **kwargs)
            
            except AuthError as e:
                return adapter.handle_auth_error(e)
                
        @wraps(func)
        def sync_wrapper(*args, **kwargs):
            try:
                # Same logic for sync functions
                token = adapter.extract_auth_token(*args, **kwargs)
                if not token:
                    raise AuthenticationError("No authentication token provided")
                
                user_data = decode_jwt(token, jwt_config)
                user_roles = user_data.get('roles', [])
                
                if required_roles and not has_required_roles(user_roles, required_roles):
                    raise AuthorizationError(
                        f"Access denied. Required roles: {required_roles}, User roles: {user_roles}"
                    )
                
                if 'user' not in kwargs:
                    kwargs['user'] = user_data
                
                return func(*args, **kwargs)
                
            except AuthError as e:
                return adapter.handle_auth_error(e)
                
        return async_wrapper if is_async else sync_wrapper
    return decorator


def decode_jwt(token: str, jwt_config: JWTConfig) -> Dict[str, Any]:
    """Decode and validate JWT token"""
    try:
        # Decode JWT with validation
        payload = jwt.decode(
            token,
            jwt_config.secret,
            algorithms=[jwt_config.algorithm],
            options={"verify_exp": jwt_config.verify_exp},
            leeway=jwt_config.leeway
        )
        
        # Extract standard user data
        return {
            'user_id': payload.get('sub'),
            'username': payload.get('username'),
            'email': payload.get('email'),
            'roles': payload.get('roles', []),
            'permissions': payload.get('permissions', []),
            'token_payload': payload  # Full payload for custom claims
        }
        
    except jwt.ExpiredSignatureError:
        raise TokenError("Token has expired")
    except jwt.InvalidSignatureError:
        raise TokenError("Invalid token signature")
    except jwt.InvalidTokenError as e:
        raise TokenError(f"Invalid token: {str(e)}")


def has_required_roles(user_roles: List[str], required_roles: List[str]) -> bool:
    if not user_roles or not required_roles:
        return False
    """Check if user has at least one of the required roles"""
    return any(role in user_roles for role in required_roles)


# Convenience functions for different frameworks (same pattern as validation.py)
def authorize_flask(required_roles: Optional[List[str]] = None, **kwargs):
    """Convenience function for Flask"""
    return authorize_request(required_roles, adapter=FlaskAdapter(), **kwargs)


def authorize_django(required_roles: Optional[List[str]] = None, **kwargs):
    """Convenience function for Django"""
    return authorize_request(required_roles, adapter=DjangoAdapter(), **kwargs)


def authorize_fastapi(required_roles: Optional[List[str]] = None, **kwargs):
    """Convenience function for FastAPI"""
    return authorize_request(required_roles, adapter=FastAPIAdapter(), **kwargs)


def authorize_generic(required_roles: Optional[List[str]] = None, **kwargs):
    """Convenience function for generic/custom frameworks"""
    return authorize_request(required_roles, adapter=GenericAdapter(), **kwargs)


# Usage Examples:
"""
# SECURE: Environment-based configuration (RECOMMENDED):
# Set environment variable:
# export JWT_SECRET="your-very-long-secret-key-at-least-32-chars"

# Option 1: Auto-configure from environment (zero-config)
@authorize_flask(['admin'])  # Automatically loads JWT_SECRET from env
def admin_endpoint():
    pass

# Option 2: Explicit configuration (still loads from env if secret not provided)
from apigateway.core.auth import configure_jwt
configure_jwt()  # Loads from JWT_SECRET environment variable
# OR
configure_jwt(secret=os.getenv('JWT_SECRET'))  # Explicit env loading

# INSECURE: Hardcoded secret (NOT RECOMMENDED - only for testing):
configure_jwt(secret="your-secret-key-for-development-only")

# Framework examples with environment-based config:
@authorize_flask()  # Any authenticated user
def protected_endpoint(user):
    return {"user_id": user['user_id']}

@authorize_flask(['admin'])  # Admin only
def admin_only(user):
    return {"admin": user['username']}

@authorize_fastapi(['admin', 'moderator'])  # Admin OR moderator
async def moderate_content(user: dict):
    return {"moderator": user['user_id']}

# Combined with validation (secure by default):
@validate_flask(CreateUserSchema)
@authorize_flask(['admin'])  
def create_user(validated, user):
    return {
        "message": f"Admin {user['username']} created user {validated.username}",
        "created_by": user['user_id']
    }

# Docker/Production environment setup:
# docker run -e JWT_SECRET="$(openssl rand -base64 32)" your-app

# Development .env file:
# JWT_SECRET=your-development-secret-key-at-least-32-characters-long
"""