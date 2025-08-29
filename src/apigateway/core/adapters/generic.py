from typing import Any, Dict
from apigateway.core.adapters.base_adapter import FrameworkAdapter
from apigateway.exceptions.GatewayValidationError import GatewayValidationError

class GenericAdapter(FrameworkAdapter):
    """Generic adapter - ignores function params, injects 'validated'"""
    
    def extract_request_data(self, *args, **kwargs) -> Dict[str, Any]:
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
        # Re-raise for custom handling
        raise error