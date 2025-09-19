# core/auth.py
import inspect
import json
import base64
import os  # NEW: For reading environment variables
from functools import wraps
from typing import Callable, Dict, Any, List, Optional

import jwt  # NEW: Import PyJWT

from apigateway.core.adapters.base_adapter import FrameworkAdapter
from apigateway.core.adapters.django import DjangoAdapter
from apigateway.core.adapters.fastapi import FastAPIAdapter
from apigateway.core.adapters.flask import FlaskAdapter
from apigateway.core.adapters.generic import GenericAdapter
from apigateway.exceptions.AuthError import AuthError, AuthenticationError, AuthorizationError, TokenError


def authorize_request(
    required_roles: Optional[List[str]] = None,
    adapter: Optional[FrameworkAdapter] = None,
    secret_key: Optional[str] = None,  # NEW: Secret key for verification
    algorithms: Optional[List[str]] = None,  # NEW: Algorithms for verification
):
    """
    Framework-agnostic RBAC authorization decorator with JWT verification.
    
    Args:
        required_roles: List of roles required to access this endpoint.
        adapter: Framework adapter (if None, uses GenericAdapter).
        secret_key: The secret key to verify the JWT signature.
                    Defaults to os.environ.get('JWT_SECRET_KEY').
        algorithms: A list of allowed algorithms (e.g., ['HS256']).
                    Defaults to os.environ.get('JWT_ALGORITHM', 'HS256').
    
    Pipeline:
        extract_token → verify_and_decode → extract_roles → check_roles → function
    """
    
    # Use GenericAdapter if no adapter specified
    if adapter is None:
        adapter = GenericAdapter()

    # MODIFIED: Load secret and algorithm from env vars if not provided
    secret_key = secret_key or os.environ.get('JWT_SECRET_KEY')
    if not secret_key:
        raise ValueError("A secret_key is required for JWT verification. Provide it directly or set JWT_SECRET_KEY environment variable.")

    algorithms = algorithms or [os.environ.get('JWT_ALGORITHM', 'HS256')]
    
    # Default to empty list if no roles required (just check token validity)
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
                
                # Step 2: MODIFIED - Verify signature and decode payload
                user_data = verify_and_decode_token(token, secret_key, algorithms)
                
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
                
                # MODIFIED - Verify signature and decode payload
                user_data = verify_and_decode_token(token, secret_key, algorithms)
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


def verify_and_decode_token(
    token: str,
    secret_key_or_pubkey: str,
    algorithms: List[str],
    custom_validators: Optional[List[Callable[[Dict[str, Any]], None]]] = None
) -> Dict[str, Any]:
    """
    Decode and VERIFY a JWT token's signature and standard claims (exp, iat).
    Supports both symmetric (HS256) and asymmetric (RS256, ES256) algorithms.
    Then run optional custom validators (revocation, rotation, etc.).
    """
    try:
        # For RS256/ES256, secret_key_or_pubkey should be a PEM-formatted public key
        payload = jwt.decode(
            token,
            secret_key_or_pubkey,
            algorithms=algorithms,
            options={"require": ["exp", "iat"]}  # enforce presence of claims
        )

        # Run extra checks if provided
        if custom_validators:
            for validator in custom_validators:
                validator(payload)  # raise exception if invalid

        return {
            'user_id': payload.get('sub'),
            'username': payload.get('username'),
            'email': payload.get('email'),
            'roles': payload.get('roles', []),
            'permissions': payload.get('permissions', []),
            'token_payload': payload
        }

    except jwt.ExpiredSignatureError:
        raise TokenError("Token has expired")
    except jwt.InvalidTokenError as e:
        raise TokenError(f"Invalid token: {str(e)}")


def has_required_roles(user_roles: List[str], required_roles: List[str]) -> bool:
    """Check if user has at least one of the required roles"""
    if not user_roles or not required_roles:
        return False
    return any(role in user_roles for role in required_roles)


# MODIFIED: Convenience functions now accept verification parameters
def authorize_flask(required_roles: Optional[List[str]] = None, secret_key: Optional[str] = None, algorithms: Optional[List[str]] = None):
    """Convenience function for Flask"""
    return authorize_request(required_roles, adapter=FlaskAdapter(), secret_key=secret_key, algorithms=algorithms)


def authorize_django(required_roles: Optional[List[str]] = None, secret_key: Optional[str] = None, algorithms: Optional[List[str]] = None):
    """Convenience function for Django"""
    return authorize_request(required_roles, adapter=DjangoAdapter(), secret_key=secret_key, algorithms=algorithms)


def authorize_fastapi(required_roles: Optional[List[str]] = None, secret_key: Optional[str] = None, algorithms: Optional[List[str]] = None):
    """Convenience function for FastAPI"""
    return authorize_request(required_roles, adapter=FastAPIAdapter(), secret_key=secret_key, algorithms=algorithms)


def authorize_generic(required_roles: Optional[List[str]] = None, secret_key: Optional[str] = None, algorithms: Optional[List[str]] = None):
    """Convenience function for generic/custom frameworks"""
    return authorize_request(required_roles, adapter=GenericAdapter(), secret_key=secret_key, algorithms=algorithms)


# Usage Examples:
"""
# Ensure your secret key is set as an environment variable or passed directly
# For example: export JWT_SECRET_KEY='your-super-secret-key'

# Now, all endpoints are protected by full JWT validation.

# With secret passed directly:
MY_SECRET = 'your-super-secret-key'

@authorize_flask(['admin'], secret_key=MY_SECRET)
def admin_only(user):
    return {"admin": user['username']}

# With secret read from environment variables:
@authorize_fastapi(['admin', 'moderator'])
async def moderate_content(user: dict):
    return {"moderator": user['user_id']}

# An expired or invalid token will now raise a TokenError,
# which is handled by the adapter to return a 401/403 response.

# Expected JWT payload structure (exp and iat are now validated):
{
    "sub": "user123",
    "username": "john_doe",
    "email": "john@example.com",
    "roles": ["user", "admin"],
    "permissions": ["read", "write"],
    "exp": 1758349234,          # Expiration time (Unix timestamp) - NOW VALIDATED
    "iat": 1758345634           # Issued at time (Unix timestamp) - NOW VALIDATED
}
"""