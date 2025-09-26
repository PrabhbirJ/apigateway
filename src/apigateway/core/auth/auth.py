# core/auth.py
import inspect
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
    token_decoder: Optional[Callable[[str], Dict[str, Any]]] = None,
    adapter: Optional[FrameworkAdapter] = None,
    custom_validators: Optional[List[Callable[[Dict[str, Any]], None]]] = None,
):
    """
    Framework-agnostic authorization decorator.
    
    Args:
        required_roles: List of roles required to access this endpoint
        token_decoder: Function to decode token string -> user dict
        adapter: Framework adapter (if None, uses GenericAdapter)
        custom_validators: Optional additional validation functions
    
    The token_decoder function should:
    - Take a token string as input
    - Return a dict with user info: {"user_id": "...", "roles": [...], ...}
    - Raise an exception if token is invalid/expired
    
    Example token_decoder:
        def my_jwt_decoder(token: str) -> Dict[str, Any]:
            payload = jwt.decode(token, MY_SECRET, algorithms=['HS256'])
            return {
                'user_id': payload['sub'],
                'username': payload.get('username'),
                'roles': payload.get('roles', [])
            }
    """
    
    # Use GenericAdapter if no adapter specified
    if adapter is None:
        adapter = GenericAdapter()
    
    # Default to empty list if no roles required (just check authentication)
    required_roles = required_roles or []
    custom_validators = custom_validators or []
    
    if not token_decoder:
        raise ValueError(
            "token_decoder is required. Please provide a function that decodes your tokens.\n"
            "Example: lambda token: jwt.decode(token, YOUR_SECRET, algorithms=['HS256'])"
        )
    
    def decorator(func: Callable):
        is_async = inspect.iscoroutinefunction(func)
        
        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            try:
                # Step 1: Extract token from request
                token = adapter.extract_auth_token(*args, **kwargs)
                if not token:
                    raise AuthenticationError("No authentication token provided")
                
                # Step 2: Decode token using programmer's decoder
                try:
                    user_data = token_decoder(token)
                except Exception as e:
                    raise TokenError(f"Token decoding failed: {str(e)}")
                
                # Step 3: Run custom validators if provided
                for validator in custom_validators:
                    try:
                        validator(user_data)
                    except Exception as e:
                        raise AuthorizationError(f"Authorization validation failed: {str(e)}")
                
                # Step 4: Check roles
                user_roles = user_data.get('roles', [])
                if required_roles and not has_required_roles(user_roles, required_roles):
                    raise AuthorizationError(
                        f"Access denied. Required roles: {required_roles}, User roles: {user_roles}"
                    )
                
                # Step 5: Inject user data
                if 'user' not in kwargs:
                    kwargs['user'] = user_data
                
                return await func(*args, **kwargs)
            
            except AuthError as e:
                return adapter.handle_auth_error(e)
                
        @wraps(func)
        def sync_wrapper(*args, **kwargs):
            try:
                token = adapter.extract_auth_token(*args, **kwargs)
                if not token:
                    raise AuthenticationError("No authentication token provided")
                
                try:
                    user_data = token_decoder(token)
                except Exception as e:
                    raise TokenError(f"Token decoding failed: {str(e)}")
                
                for validator in custom_validators:
                    try:
                        validator(user_data)
                    except Exception as e:
                        raise AuthorizationError(f"Authorization validation failed: {str(e)}")
                
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


def has_required_roles(user_roles: List[str], required_roles: List[str]) -> bool:
    """Check if user has at least one of the required roles"""
    if not user_roles or not required_roles:
        return False
    return any(role in user_roles for role in required_roles)


# Convenience functions for different frameworks
def authorize_flask(
    required_roles: Optional[List[str]] = None, 
    token_decoder: Optional[Callable[[str], Dict[str, Any]]] = None,
    **kwargs
):
    """Convenience function for Flask"""
    return authorize_request(required_roles, token_decoder, FlaskAdapter(), **kwargs)


def authorize_django(
    required_roles: Optional[List[str]] = None, 
    token_decoder: Optional[Callable[[str], Dict[str, Any]]] = None,
    **kwargs
):
    """Convenience function for Django"""
    return authorize_request(required_roles, token_decoder, DjangoAdapter(), **kwargs)


def authorize_fastapi(
    required_roles: Optional[List[str]] = None, 
    token_decoder: Optional[Callable[[str], Dict[str, Any]]] = None,
    **kwargs
):
    """Convenience function for FastAPI"""
    return authorize_request(required_roles, token_decoder, FastAPIAdapter(), **kwargs)


def authorize_generic(
    required_roles: Optional[List[str]] = None, 
    token_decoder: Optional[Callable[[str], Dict[str, Any]]] = None,
    **kwargs
):
    """Convenience function for generic/custom frameworks"""
    return authorize_request(required_roles, token_decoder, GenericAdapter(), **kwargs)


# Helper functions programmers can use (optional)
def create_jwt_decoder(secret_key: str, algorithm: str = 'HS256'):
    """
    Helper function to create a JWT decoder (OPTIONAL - programmers can make their own)
    """
    import jwt
    
    def decoder(token: str) -> Dict[str, Any]:
        try:
            payload = jwt.decode(token, secret_key, algorithms=[algorithm])
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
    
    return decoder


# Usage Examples:
"""
# PROGRAMMER'S RESPONSIBILITY: Create token decoder with their secret
import jwt

JWT_SECRET = "my-app-secret-key"

def my_jwt_decoder(token: str) -> Dict[str, Any]:
    payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
    return {
        'user_id': payload['sub'],
        'username': payload.get('username'),
        'roles': payload.get('roles', [])
    }

# Or use helper (still programmer's choice):
my_decoder = create_jwt_decoder(JWT_SECRET, 'HS256')

# Now use in decorators:
@authorize_flask(['admin'], token_decoder=my_jwt_decoder)
def admin_endpoint(user):
    return {"admin": user['username']}

@authorize_flask(['user'], token_decoder=my_decoder)
def user_endpoint(user):
    return {"user_id": user['user_id']}

# With custom validation:
def check_not_banned(user_data):
    if user_data.get('status') == 'banned':
        raise Exception("User is banned")

@authorize_flask(
    ['user'], 
    token_decoder=my_decoder,
    custom_validators=[check_not_banned]
)
def protected_endpoint(user):
    return {"message": "success"}

# Different token types - programmer's choice:
def session_token_decoder(token: str):
    # Look up session in database
    session = Session.objects.get(token=token)
    return {
        'user_id': session.user_id,
        'roles': session.user.roles
    }

@authorize_flask(['user'], token_decoder=session_token_decoder)
def session_protected(user):
    return {"user_id": user['user_id']}
"""