# core/adapters/django.py
import json
from typing import Any, Dict, Optional
from apigateway.core.adapters.base_adapter import FrameworkAdapter
from apigateway.exceptions.AuthError import AuthError, AuthenticationError, TokenError
from apigateway.exceptions.GatewayValidationError import GatewayValidationError
from django.http import JsonResponse


class DjangoAdapter(FrameworkAdapter):
    """Adapter for Django framework"""
    
    def extract_request_data(self, request, *args, **kwargs) -> Dict[str, Any]:
        """Extract request data from Django request object"""
        data = {}
        
        # JSON body
        if hasattr(request, 'content_type') and 'application/json' in request.content_type:
            try:
                json_data = json.loads(request.body.decode('utf-8'))
                if json_data:
                    data.update(json_data)
            except (json.JSONDecodeError, UnicodeDecodeError):
                raise GatewayValidationError("Invalid JSON in request body", [])
        
        # Form data (POST)
        if hasattr(request, 'POST') and request.POST:
            for key, values in request.POST.lists():
                data[key] = values[0] if len(values) == 1 else values
        
        # Query parameters (GET)
        if hasattr(request, 'GET') and request.GET:
            for key, values in request.GET.lists():
                data[key] = values[0] if len(values) == 1 else values
        
        return data
    
    def handle_validation_error(self, error: GatewayValidationError) -> Any:
        """Return Django-compatible validation error response"""
        return JsonResponse({
            "error": error.message,
            "code": error.code,
            "details": error.details
        }, status=422)

    def extract_files(self, request, *args, **kwargs) -> Dict[str, Any]:
        """Extract uploaded files from Django request"""
        files = {}
        if hasattr(request, 'FILES') and request.FILES:
            for field_name in request.FILES:
                file_list = request.FILES.getlist(field_name)
                files[field_name] = file_list[0] if len(file_list) == 1 else file_list
        return files

    def extract_auth_token(self, request, *args, **kwargs) -> Optional[str]:
        """Extract bearer token from Django request"""
        auth_header = request.META.get('HTTP_AUTHORIZATION')
        if not auth_header:
            return None
            
        try:
            return self._extract_bearer_token(auth_header)
        except AuthError:
            return None  # Invalid format, return None

    def extract_rate_limit_key_info(self, request, *args, **kwargs) -> Dict[str, Any]:
        """Extract rate limiting information from Django request"""
        # Get real IP address (handle proxies)
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            client_ip = x_forwarded_for.split(',')[0].strip()
        else:
            client_ip = request.META.get('REMOTE_ADDR', 'unknown')
        
        return {
            'client_ip': client_ip,
            'user_agent': request.META.get('HTTP_USER_AGENT', 'unknown'),
            'request': request
        }

    def handle_auth_error(self, error: AuthError) -> Any:
        """Return Django-compatible auth error response"""
        status_code = self._get_auth_status_code(error)
        
        return JsonResponse({
            "error": error.message,
            "code": error.code,
            "details": error.details
        }, status=status_code)

    def handle_rate_limit_error(self, error) -> Any:
        """Return Django-compatible rate limit error response"""
        from apigateway.exceptions.RateLimitError import RateLimitError
        
        response_data = {
            "error": error.message,
            "code": error.code,
            "details": error.details
        }
        
        response = JsonResponse(response_data, status=429)
        
        # Add standard rate limit headers
        if error.details:
            if 'retry_after' in error.details and error.details['retry_after']:
                response['Retry-After'] = str(error.details['retry_after'])
            if 'limit' in error.details:
                response['X-RateLimit-Limit'] = str(error.details['limit'])
            if 'remaining' in error.details:
                response['X-RateLimit-Remaining'] = str(error.details.get('remaining', 0))
            if 'reset_time' in error.details:
                response['X-RateLimit-Reset'] = str(error.details['reset_time'])
        
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