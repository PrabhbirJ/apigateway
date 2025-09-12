# core/adapters/flask.py
from typing import Any, Dict, Optional
from apigateway.core.adapters.base_adapter import FrameworkAdapter
from apigateway.exceptions.GatewayValidationError import GatewayValidationError
from apigateway.exceptions.AuthError import AuthError, AuthenticationError, TokenError
from flask import request, jsonify


class FlaskAdapter(FrameworkAdapter):
    """Adapter for Flask framework"""
    
    def extract_request_data(self, *args, **kwargs) -> Dict[str, Any]:
        """Extract request data from Flask request object"""
        data = {}

        # JSON body - be more permissive about content types
        if request.is_json or (
            request.content_type and 
            'application/json' in request.content_type.lower()
        ):
            try:
                json_data = request.get_json(force=True, silent=False)
                if json_data:
                    data.update(json_data)
            except Exception:
                raise GatewayValidationError("Invalid JSON in request body", [])
        
        # Form data
        if request.form:
            for key in request.form:
                values = request.form.getlist(key)
                data[key] = values[0] if len(values) == 1 else values

        # Query parameters
        if request.args:
            for key in request.args:
                values = request.args.getlist(key)
                data[key] = values[0] if len(values) == 1 else values

        return data
    
    def handle_validation_error(self, error: GatewayValidationError) -> Any:
        """Return Flask-compatible validation error response"""
        response = jsonify({
            "error": error.message,
            "code": error.code,
            "details": error.details
        })
        response.status_code = 422  # Unprocessable Entity
        return response

    def extract_files(self, *args, **kwargs) -> Dict[str, Any]:
        """Extract uploaded files from Flask request"""
        files = {}
        if request.files:
            for field_name in request.files:
                file_list = request.files.getlist(field_name)
                files[field_name] = file_list[0] if len(file_list) == 1 else file_list
        return files

    def extract_auth_token(self, *args, **kwargs) -> Optional[str]:
        """Extract bearer token from Flask request"""
        auth_header = request.headers.get("Authorization")
        if not auth_header:
            return None
            
        try:
            return self._extract_bearer_token(auth_header)
        except AuthError:
            return None  # Invalid format, return None

    def handle_auth_error(self, error: AuthError) -> Any:
        """Return Flask-compatible auth error response"""
        # Map error types to appropriate HTTP status codes
        status_code = self._get_auth_status_code(error)
        
        response = jsonify({
            "error": error.message,
            "code": error.code,
            "details": error.details
        })
        response.status_code = status_code
        return response

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