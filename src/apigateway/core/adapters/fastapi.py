# FastAPI Adapter - Simplified Post-Validator Only Approach
from typing import Any, Dict
from apigateway.core.adapters.base_adapter import FrameworkAdapter
from apigateway.exceptions.GatewayValidationError import GatewayValidationError
from pydantic import BaseModel


class FastAPIAdapter(FrameworkAdapter):
    """
    Simplified FastAPI adapter that works with FastAPI's pre-validated models.
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
        
        # No Pydantic model found - this shouldn't happen with FastAPI DI
        # Return empty dict for raw mode (fallback)
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
        from fastapi import HTTPException
        raise HTTPException(
            status_code=422,
            detail={
                "error": error.message,
                "details": error.details
            }
        )