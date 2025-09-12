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