# core/adapters/base_adapter.py
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
from apigateway.exceptions.GatewayValidationError import GatewayValidationError
from apigateway.exceptions.AuthError import AuthError


class FrameworkAdapter(ABC):
    """
    Abstract adapter for different web frameworks.
    
    This adapter handles framework-specific operations for:
    - Request data extraction (validation)
    - File upload handling
    - Authentication header extraction
    - Error response formatting
    """
    
    @abstractmethod
    def extract_request_data(self, *args, **kwargs) -> Dict[str, Any]:
        """Extract request data from framework-specific request object"""
        pass
    
    @abstractmethod
    def handle_validation_error(self, error: GatewayValidationError) -> Any:
        """Handle validation error in framework-specific way"""
        pass
    
    @abstractmethod
    def extract_files(self, *args, **kwargs) -> Dict[str, Any]:
        """Extract uploaded files from framework-specific request object"""
        pass
    
    @abstractmethod
    def extract_auth_token(self, *args, **kwargs) -> Optional[str]:
        """
        Extract bearer token from Authorization header.
        
        Returns:
            Bearer token string or None if not present/invalid
        """
        pass
    
    @abstractmethod
    def handle_auth_error(self, error: AuthError) -> Any:
        """Handle authentication/authorization error in framework-specific way"""
        pass
    
    @abstractmethod
    def extract_rate_limit_key_info(self, *args, **kwargs) -> Dict[str, Any]:
        """
        Extract information needed for rate limiting key generation.
        
        Returns:
            Dict containing:
            - 'client_ip': Client IP address
            - 'user_agent': User agent string (optional)
            - 'request': Framework request object
        """
        pass
    
    @abstractmethod
    def handle_rate_limit_error(self, error) -> Any:
        """Handle rate limit error in framework-specific way (429 Too Many Requests)"""
        pass
    
    @abstractmethod
    def extract_request_logging_info(self, *args, **kwargs) -> Dict[str, Any]:
        """
        Extract comprehensive request information for logging.
        
        This method should extract detailed request information that will be
        used for structured logging and audit trails.
        
        Args:
            *args, **kwargs: Framework-specific request parameters
            
        Returns:
            Dict containing:
            - 'method': HTTP method (GET, POST, etc.)
            - 'path': Request path/URL path
            - 'headers': Request headers as dict (keys should be lowercase)
            - 'query_params': Query parameters as dict
            - 'client_ip': Client IP address (handle proxies/load balancers)
            - 'user_agent': User agent string
            - 'content_type': Content-Type header value
            - 'content_length': Content-Length header value (int or None)
            - 'url': Full URL (optional, for audit purposes)
            - 'scheme': URL scheme (http/https, optional)
            - 'endpoint': Framework-specific endpoint identifier (optional)
        """
        pass
    
    @abstractmethod
    def extract_response_logging_info(self, response) -> Dict[str, Any]:
        """
        Extract response information for logging.
        
        This method should extract information about the response that will be
        sent back to the client for logging and monitoring purposes.
        
        Args:
            response: Framework-specific response object or data
            
        Returns:
            Dict containing:
            - 'status': HTTP status code (int)
            - 'size': Response size in bytes (int or None)
            - 'cache_status': Cache status/headers (str or None)
            - 'content_type': Response Content-Type (str or None)
        """
        pass
    