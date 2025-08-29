# Django Adapter
import json
from typing import Any, Dict
from apigateway.core.adapters.base_adapter import FrameworkAdapter
from apigateway.exceptions.GatewayValidationError import GatewayValidationError


class DjangoAdapter(FrameworkAdapter):
    """Adapter for Django framework"""
    
    def extract_request_data(self, request, *args, **kwargs) -> Dict[str, Any]:
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
                if len(values) == 1:
                    data[key] = values[0]       # flatten
                else:
                    data[key] = values          # keep list if multiple
        
        # Query parameters (GET)
        if hasattr(request, 'GET') and request.GET:
            for key, values in request.GET.lists():
                if len(values) == 1:
                    data[key] = values[0]
                else:
                    data[key] = values
        
        return data
    
    def handle_validation_error(self, error: GatewayValidationError) -> Any:
        from django.http import JsonResponse
        return JsonResponse({
            "error": error.message,
            "details": error.details
        }, status=400)
    