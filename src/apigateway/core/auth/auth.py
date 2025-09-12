# core/auth.py
import inspect
import json
import base64
from functools import wraps
from typing import Callable, Dict, Any, List, Optional
from apigateway.core.adapters.base_adapter import FrameworkAdapter
from apigateway.core.adapters.django import DjangoAdapter
from apigateway.core.adapters.fastapi import FastAPIAdapter
from apigateway.core.adapters.flask import FlaskAdapter
from apigateway.core.adapters.generic import GenericAdapter
from apigateway.exceptions.AuthError import AuthError, AuthenticationError, AuthorizationError, TokenError


def authorize_request(
    required_roles: Optional[List[str]] = None,
    adapter: Optional[FrameworkAdapter] = None,
):
    """
    Framework-agnostic RBAC authorization decorator
    
    Args:
        required_roles: List of roles required to access this endpoint
        adapter: Framework adapter (if None, uses GenericAdapter)
    
    Pipeline:
        extract_token → decode_payload → extract_roles → check_roles → function
    """
    
    # Use GenericAdapter if no adapter specified
    if adapter is None:
        adapter = GenericAdapter()
    
    # Default to empty list if no roles required (just check token presence)
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
                
                # Step 2: Decode payload without verification
                user_data = decode_token_payload(token)
                
                # Step 3: Extract roles from payload
                user_roles = user_data.get('roles', [])
                
                # Step 4: Check if user has required roles
                if required_roles and not has_required_roles(user_roles, required_roles):
                    raise AuthorizationError(
                        f"Access denied. Required roles: {required_roles}, User roles: {user_roles}"
                    )
                
                # Step 5: Inject user data into kwargs
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
                
                user_data = decode_token_payload(token)
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


def decode_token_payload(token: str) -> Dict[str, Any]:
    """
    Decode JWT payload WITHOUT verification - RBAC only
    
    WARNING: This does NOT validate the token signature or expiration.
    Only use this when authentication is handled elsewhere and you only need RBAC.
    """
    try:
        # Split JWT token (header.payload.signature)
        parts = token.split('.')
        if len(parts) != 3:
            raise TokenError("Invalid token format - must have 3 parts")
        
        # Decode payload (second part)
        payload_part = parts[1]
        
        # Add padding if needed for base64 decoding
        padding = '=' * (4 - len(payload_part) % 4)
        payload_part += padding
        
        # Decode base64 payload
        payload_bytes = base64.urlsafe_b64decode(payload_part)
        payload = json.loads(payload_bytes.decode('utf-8'))
        
        # Extract standard user data
        return {
            'user_id': payload.get('sub'),
            'username': payload.get('username'),
            'email': payload.get('email'),
            'roles': payload.get('roles', []),
            'permissions': payload.get('permissions', []),
            'token_payload': payload  # Full payload for custom claims
        }
        
    except (ValueError, json.JSONDecodeError, UnicodeDecodeError) as e:
        raise TokenError(f"Failed to decode token payload: {str(e)}")
    except Exception as e:
        raise TokenError(f"Invalid token: {str(e)}")


def has_required_roles(user_roles: List[str], required_roles: List[str]) -> bool:
    """Check if user has at least one of the required roles"""
    if not user_roles or not required_roles:
        return False
    return any(role in user_roles for role in required_roles)


# Convenience functions for different frameworks
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
# RBAC-only authorization (no JWT verification):

@authorize_flask()  # Any user with a token (no role check)
def protected_endpoint(user):
    return {"user_id": user['user_id']}

@authorize_flask(['admin'])  # Admin role required
def admin_only(user):
    return {"admin": user['username']}

@authorize_fastapi(['admin', 'moderator'])  # Admin OR moderator role required
async def moderate_content(user: dict):
    return {"moderator": user['user_id']}

# Combined with validation:
@validate_flask(CreateUserSchema)
@authorize_flask(['admin'])  
def create_user(validated, user):
    return {
        "message": f"User {user['username']} created {validated.username}",
        "created_by": user['user_id']
    }

# Multi-role access patterns:
@authorize_flask(['admin', 'manager', 'supervisor'])  # Any of these roles
def management_endpoint(user):
    return {"access_level": "management"}

# Custom role checking in your function:
@authorize_flask()  # Just check token presence
def flexible_endpoint(user):
    user_roles = user.get('roles', [])
    
    if 'admin' in user_roles:
        return {"level": "full_access"}
    elif 'user' in user_roles:
        return {"level": "limited_access"}
    else:
        return {"level": "read_only"}

# Expected JWT payload structure:
{
    "sub": "user123",           # user_id
    "username": "john_doe",     # username
    "email": "john@example.com", # email
    "roles": ["user", "admin"], # roles for RBAC
    "permissions": ["read", "write"], # optional permissions
    "exp": 1234567890,          # expiration (ignored)
    "iat": 1234567890           # issued at (ignored)
}
"""