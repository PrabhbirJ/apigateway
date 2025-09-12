# Flask Adapter - Fixed Version
from typing import Any, Dict
from apigateway.core.adapters.base_adapter import FrameworkAdapter
from apigateway.exceptions.GatewayValidationError import GatewayValidationError


class FlaskAdapter(FrameworkAdapter):
    """Adapter for Flask framework"""
    
    def extract_request_data(self, *args, **kwargs) -> Dict[str, Any]:
        from flask import request
        
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
                # If get_json fails, try to give a helpful error
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
        from flask import jsonify
        response = jsonify({
            "error": error.message,
            "details": error.details
        })
        response.status_code = 422  # Consistent with FastAPI
        return response
    

    
    def extract_files(self, *args, **kwargs) -> Dict[str, Any]:
        from flask import request
        
        files = {}
        
        if request.files:
            for field_name in request.files:
                file_list = request.files.getlist(field_name)
                if len(file_list) == 1:
                    files[field_name] = file_list[0]  # Single file
                else:
                    files[field_name] = file_list     # Multiple files
        
        return files