# core/adapters/generic.py
from typing import Any, Dict, Optional
from apigateway.core.adapters.base_adapter import FrameworkAdapter
from apigateway.exceptions.GatewayValidationError import GatewayValidationError
from apigateway.exceptions.AuthError import AuthError, AuthenticationError, TokenError


class GenericAdapter(FrameworkAdapter):
    """Generic adapter - ignores function params, injects 'validated'"""
    
    def extract_request_data(self, *args, **kwargs) -> Dict[str, Any]:
        """Extract request data from the first argument"""
        # Get the first argument as request_data (like Flask gets request data)
        if not args:
            return {}
        
        request_data = args[0]
        
        if request_data is None:
            return {}
        
        if isinstance(request_data, dict):
            return request_data
        
        if hasattr(request_data, "model_dump"):  # Pydantic v2
            return request_data.model_dump()
        
        if hasattr(request_data, "dict"):  # Pydantic v1
            return request_data.dict()
        
        if hasattr(request_data, "__dict__"):  # Arbitrary object
            return dict(request_data.__dict__)
        
        raise GatewayValidationError("Unsupported request data type", [])
    
    def handle_validation_error(self, error: GatewayValidationError) -> Any:
        """Re-raise for custom handling"""
        raise error
    
    def extract_files(self, *args, **kwargs) -> Dict[str, Any]:
        """Extract files from generic request (basic implementation)"""
        # For generic adapter, try to find files in common places
        files = {}
        
        # Check kwargs for file-like objects
        for key, value in kwargs.items():
            if self._is_file_like(value):
                files[key] = value
            elif isinstance(value, list) and value and self._is_file_like(value[0]):
                files[key] = value
        
        # Check first argument if it's an object with files attribute
        if args and hasattr(args[0], 'files'):
            files_attr = getattr(args[0], 'files')
            if isinstance(files_attr, dict):
                files.update(files_attr)
        
        return files
    
    def extract_auth_token(self, *args, **kwargs) -> Optional[str]:
        """Extract bearer token from generic request"""
        auth_header = None
        
        # Try to find Authorization header in various places
        # 1. Check kwargs for authorization
        if 'authorization' in kwargs:
            auth_header = kwargs['authorization']
        elif 'auth' in kwargs:
            auth_header = kwargs['auth']
        
        # 2. Check first argument for headers attribute
        if not auth_header and args:
            request_obj = args[0]
            if hasattr(request_obj, 'headers'):
                headers = request_obj.headers
                if isinstance(headers, dict):
                    auth_header = headers.get('Authorization') or headers.get('authorization')
            elif hasattr(request_obj, 'Authorization'):
                auth_header = request_obj.Authorization
            elif isinstance(request_obj, dict):
                auth_header = request_obj.get('Authorization') or request_obj.get('authorization')
        
        if not auth_header:
            return None
            
        try:
            return self._extract_bearer_token(auth_header)
        except AuthError:
            return None  # Invalid format, return None
    
    def extract_rate_limit_key_info(self, *args, **kwargs) -> Dict[str, Any]:
        """Extract rate limiting information from generic request"""
        client_ip = "unknown"
        user_agent = "unknown"
        request_obj = None
        
        # Try to extract info from first argument
        if args:
            request_obj = args[0]
            
            # Try various ways to get client IP
            if hasattr(request_obj, 'remote_addr'):
                client_ip = request_obj.remote_addr or "unknown"
            elif hasattr(request_obj, 'client_ip'):
                client_ip = request_obj.client_ip or "unknown"
            elif isinstance(request_obj, dict):
                client_ip = request_obj.get('client_ip') or request_obj.get('remote_addr') or "unknown"
            
            # Try various ways to get user agent
            if hasattr(request_obj, 'headers'):
                headers = request_obj.headers
                if isinstance(headers, dict):
                    user_agent = headers.get('User-Agent') or headers.get('user-agent') or "unknown"
            elif hasattr(request_obj, 'user_agent'):
                user_agent = request_obj.user_agent or "unknown"
            elif isinstance(request_obj, dict):
                user_agent = request_obj.get('user_agent') or request_obj.get('User-Agent') or "unknown"
        
        # Check kwargs for explicit values
        if 'client_ip' in kwargs:
            client_ip = kwargs['client_ip'] or client_ip
        if 'user_agent' in kwargs:
            user_agent = kwargs['user_agent'] or user_agent
            
        return {
            'client_ip': client_ip,
            'user_agent': user_agent,
            'request': request_obj
        }
    
    def handle_auth_error(self, error: AuthError) -> Any:
        """Handle auth error in generic way - re-raise for custom handling"""
        raise error
    
    def handle_rate_limit_error(self, error) -> Any:
        """Handle rate limit error in generic way - re-raise for custom handling"""
        raise error
    
    def _is_file_like(self, obj) -> bool:
        """Check if object is file-like"""
        # Basic check for file-like objects
        return (
            hasattr(obj, 'read') and 
            (hasattr(obj, 'name') or hasattr(obj, 'filename'))
        )
    
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