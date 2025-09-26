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

    def extract_rate_limit_key_info(self, *args, **kwargs) -> Dict[str, Any]:
        """Extract rate limiting information from Flask request"""
        # Get real IP address (handle proxies)
        if request.headers.get('X-Forwarded-For'):
            client_ip = request.headers.get('X-Forwarded-For').split(',')[0].strip()
        else:
            client_ip = request.remote_addr or "unknown"
        
        return {
            'client_ip': client_ip,
            'user_agent': request.headers.get('User-Agent', 'unknown'),
            'request': request
        }

    def handle_rate_limit_error(self, error) -> Any:
        """Return Flask-compatible rate limit error response"""
        from apigateway.exceptions.RateLimitError import RateLimitError
        
        response = jsonify({
            "error": error.message,
            "code": error.code,
            "details": error.details
        })
        response.status_code = 429  # Too Many Requests
        
        # Add standard rate limit headers
        if error.details:
            if 'retry_after' in error.details and error.details['retry_after']:
                response.headers['Retry-After'] = str(error.details['retry_after'])
            if 'limit' in error.details:
                response.headers['X-RateLimit-Limit'] = str(error.details['limit'])
            if 'remaining' in error.details:
                response.headers['X-RateLimit-Remaining'] = str(error.details.get('remaining', 0))
            if 'reset_time' in error.details:
                response.headers['X-RateLimit-Reset'] = str(error.details['reset_time'])
        
        return response

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
        
    def extract_request_logging_info(self, *args, **kwargs) -> Dict[str, Any]:
        """Extract Flask request information for logging"""
        from flask import request
        
        # Get real IP address (handle proxies and load balancers)
        client_ip = request.headers.get('X-Forwarded-For')
        if client_ip:
            # Take the first IP if multiple are present
            client_ip = client_ip.split(',')[0].strip()
        else:
            client_ip = request.environ.get('REMOTE_ADDR', 'unknown')
        
        # Extract all headers with lowercase keys for consistency
        headers = {}
        for key, value in request.headers:
            headers[key.lower()] = value
        
        return {
            'method': request.method,
            'path': request.path,
            'headers': headers,
            'query_params': dict(request.args),
            'client_ip': client_ip,
            'user_agent': request.headers.get('User-Agent', 'unknown'),
            'content_type': request.content_type,
            'content_length': request.content_length,
            'url': request.url,
            'scheme': request.scheme,
            'endpoint': request.endpoint
        }

    def extract_response_logging_info(self, response) -> Dict[str, Any]:
        """Extract Flask response information for logging"""
        if hasattr(response, 'status_code'):
            # Flask Response object
            response_size = None
            if hasattr(response, 'get_data'):
                try:
                    response_size = len(response.get_data())
                except:
                    response_size = None
            
            return {
                'status': response.status_code,
                'size': response_size,
                'cache_status': response.headers.get('Cache-Control'),
                'content_type': response.headers.get('Content-Type')
            }
        elif isinstance(response, (dict, list)):
            # JSON response that Flask will serialize
            import json
            return {
                'status': 200,
                'size': len(json.dumps(response).encode('utf-8')),
                'cache_status': None,
                'content_type': 'application/json'
            }
        else:
            # String or other response
            response_str = str(response) if response is not None else ""
            return {
                'status': 200,
                'size': len(response_str.encode('utf-8')),
                'cache_status': None,
                'content_type': 'text/plain'
            }
