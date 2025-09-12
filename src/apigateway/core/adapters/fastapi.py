# core/adapters/fastapi.py
from typing import Any, Dict, Optional
from apigateway.core.adapters.base_adapter import FrameworkAdapter
from apigateway.exceptions.AuthError import AuthError, AuthenticationError, TokenError
from apigateway.exceptions.GatewayValidationError import GatewayValidationError
from pydantic import BaseModel
from fastapi import HTTPException, Request, UploadFile


class FastAPIAdapter(FrameworkAdapter):
    """
    FastAPI adapter that works with FastAPI's pre-validated models.
    Only runs post-validators - lets FastAPI handle all validation.
    """
    
    def extract_request_data(self, *args, **kwargs) -> Dict[str, Any]:
        """
        Find FastAPI's pre-validated Pydantic model and return it as a tuple
        to signal that validation is already done.
        """
        # Look for a Pydantic model in the kwargs (most common)
        for key, value in kwargs.items():
            if isinstance(value, BaseModel):
                # Return tuple: (dict_data, validated_model)
                data = self._model_to_dict(value)
                return (data, value)
        
        # Check positional args for Pydantic models
        for arg in args:
            if isinstance(arg, BaseModel):
                data = self._model_to_dict(arg)
                return (data, arg)
        
        # No Pydantic model found - fallback to empty dict
        return {}

    def _model_to_dict(self, model: BaseModel) -> Dict[str, Any]:
        """Convert Pydantic model to dict"""
        if hasattr(model, 'model_dump'):  # Pydantic v2
            return model.model_dump()
        elif hasattr(model, 'dict'):  # Pydantic v1
            return model.dict()
        else:
            return {}
    
    def handle_validation_error(self, error: GatewayValidationError) -> Any:
        """Return FastAPI-compatible validation error response"""
        raise HTTPException(
            status_code=422,
            detail={
                "error": error.message,
                "code": error.code,
                "details": error.details
            }
        )

    def extract_files(self, *args, **kwargs) -> Dict[str, Any]:
        """Extract UploadFile objects from FastAPI dependency injection"""
        files = {}
        
        # Check kwargs for UploadFile objects (FastAPI dependency injection style)
        for key, value in kwargs.items():
            if isinstance(value, UploadFile):
                files[key] = value
            elif isinstance(value, list) and value and isinstance(value[0], UploadFile):
                files[key] = value  # Multiple files
        
        # Check positional args for UploadFile objects
        for i, arg in enumerate(args):
            if isinstance(arg, UploadFile):
                files[f"file_{i}"] = arg
            elif isinstance(arg, list) and arg and isinstance(arg[0], UploadFile):
                files[f"files_{i}"] = arg
        
        return files

    def extract_auth_info(self, *args, **kwargs) -> Dict[str, Optional[str]]:
        """Extract authentication information from FastAPI request"""
        # Find Request object in function parameters
        request = self._find_request_object(*args, **kwargs)
        
        if not request:
            # If no Request object found, we can't extract auth info
            return {
                "authorization": None,
                "bearer_token": None,
                "client_ip": "unknown",
                "user_agent": "unknown",
                "method": "unknown",
                "path": "unknown"
            }
        
        auth_header = request.headers.get("Authorization")
        bearer_token = None
        
        # Extract bearer token if present
        if auth_header:
            try:
                bearer_token = self._extract_bearer_token(auth_header)
            except AuthError:
                # Don't raise here - let the auth decorator decide what to do
                pass
        
        # Get client IP (FastAPI-specific)
        client_ip = self._get_client_ip(request)
        
        return {
            "authorization": auth_header,
            "bearer_token": bearer_token,
            "client_ip": client_ip,
            "user_agent": request.headers.get("user-agent", "unknown"),
            "method": request.method,
            "path": str(request.url.path)
        }

    def handle_auth_error(self, error: AuthError) -> Any:
        """Return FastAPI-compatible auth error response"""
        status_code = self._get_auth_status_code(error)
        
        raise HTTPException(
            status_code=status_code,
            detail={
                "error": error.message,
                "code": error.code,
                "details": error.details
            }
        )

    def _find_request_object(self, *args, **kwargs) -> Optional[Request]:
        """Find FastAPI Request object in function parameters"""
        # Check kwargs first
        for key, value in kwargs.items():
            if isinstance(value, Request):
                return value
        
        # Check positional args
        for arg in args:
            if isinstance(arg, Request):
                return arg
                
        return None

    def _extract_bearer_token(self, auth_header: str) -> str:
        """Extract bearer token from Authorization header"""
        if not auth_header:
            raise AuthenticationError("No authorization header provided")
        
        parts = auth_header.strip().split()
        if len(parts) != 2:
            raise TokenError("Invalid authorization header format")
        
        scheme, token = parts
        if scheme.lower() != "bearer":
            raise TokenError("Authorization scheme must be 'Bearer'")
        
        if not token:
            raise TokenError("Missing bearer token")
            
        return token



    def _get_auth_status_code(self, error: AuthError) -> int:
        """Map auth error types to HTTP status codes"""
        if error.code == "authentication_required":
            return 401  # Unauthorized
        elif error.code == "access_denied":
            return 403  # Forbidden  
        elif error.code == "token_error":
            return 401  # Unauthorized
        else:
            return 403  # Default to Forbidden