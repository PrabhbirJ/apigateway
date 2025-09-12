# Abstract base class for framework adapters
from abc import ABC,abstractmethod
from typing import Dict,Any
from apigateway.exceptions.GatewayValidationError import GatewayValidationError


class FrameworkAdapter(ABC):
    """Abstract adapter for different web frameworks"""
    
    @abstractmethod
    def extract_request_data(self, *args, **kwargs) -> Dict[str, Any]:
        """Extract request data from framework-specific request object"""
        pass
    
    @abstractmethod
    def handle_validation_error(self, error: GatewayValidationError) -> Any:
        """Handle validation error in framework-specific way"""
        pass
    @abstractmethod
    def extract_files(self,*args,**kwargs) -> Dict[str,Any]:
        '''Extract uploaded files from framework-specific request object'''
        pass