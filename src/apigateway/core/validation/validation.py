from functools import wraps
import inspect
from typing import Callable, Dict, Any, List, Optional
from pydantic import BaseModel, Extra, ValidationError
from apigateway.core.adapters.base_adapter import FrameworkAdapter
from apigateway.core.adapters.django import DjangoAdapter
from apigateway.core.adapters.fastapi import FastAPIAdapter
from apigateway.core.adapters.flask import FlaskAdapter
from apigateway.core.adapters.generic import GenericAdapter
from apigateway.core.enums.validation_modes import ValidationMode
from apigateway.exceptions.GatewayValidationError import GatewayValidationError
from apigateway.core.errors.formatters import default_error_formatter





def validate_request(
    model: type[BaseModel],
    adapter: Optional[FrameworkAdapter] = None,
    mode: ValidationMode = ValidationMode.STRICT,
    error_formatter: Optional[Callable[[list[dict[str, Any]]], list[dict[str, Any]]]] = None,
    pre_validators: Optional[List[Callable[[Dict[str, Any]], Dict[str, Any]]]] = None,
    post_validators: Optional[List[Callable[[BaseModel], BaseModel]]] = None,
):
    """
    Framework-agnostic validation decorator
    
    Args:
        model: Pydantic model for validation
        adapter: Framework adapter (if None, uses GenericAdapter)
        mode: Validation mode (STRICT or LENIENT)
        error_formatter: Custom error formatter
        pre_validators: List of functions to run on raw data before Pydantic validation
        post_validators: List of functions to run on validated model after Pydantic validation
    
    Pipeline:
        extract_request_data → pre_validators → pydantic_validation → post_validators → function
    """
    
    extra = model.model_config['extra']
    if mode==ValidationMode.PERMISSIVE:
    
        extra_str = str(extra).lower()
        print(extra_str)
        is_forbid_or_ignore = (
            extra_str == "forbid" or 
            extra_str == "extra.forbid" or  # Handle enum case
            extra == "forbid" or  # Direct string comparison
            extra == "ignore" or
            extra_str == "ignore" or
            extra_str == "extra.ignore"
        )

        if not is_forbid_or_ignore:
            raise TypeError(
                f"Schema {model.__name__} must set `extra='forbid'` or `extra='ignore'` in its model_config"
            )
    else:
        extra_str = str(extra).lower()
        print(extra_str)
        is_forbid = (
            extra_str == "forbid" or 
            extra_str == "extra.forbid" or  # Handle enum case
            extra == "forbid" # Direct string comparison 
        )

        if not is_forbid:
            raise TypeError(
                f"Schema {model.__name__} must set `extra='forbid'` in its model_config"
            )
    # Use GenericAdapter if no adapter specified
    if adapter is None:
        adapter = GenericAdapter()
    
    # Default to empty lists if None
    pre_validators = pre_validators or []
    post_validators = post_validators or []
    
    def decorator(func: Callable):
        is_async = inspect.iscoroutinefunction(func)
        
        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            try:
                # Step 1: Extract request data
                request_data = adapter.extract_request_data(*args, **kwargs)

                # NEW: detect if adapter returned a (dict, validated_model) tuple
                validated_model = None
                if isinstance(request_data, tuple) and len(request_data) == 2:
                    request_data, validated_model = request_data

                # Step 2: Run pre-validators (only if working with raw dict)
                if validated_model is None:
                    for pre_validator in pre_validators:
                        request_data = pre_validator(request_data)

                    # Step 3: Pydantic validation
                    validated = model.model_validate(
                        request_data,
                        strict=(mode == ValidationMode.STRICT),
                    )
                else:
                    # Skip validation, use FastAPI's pre-validated model
                    validated = validated_model

                # Step 4: Run post-validators
                for post_validator in post_validators:
                    try:
                        validated = post_validator(validated)
                    except Exception as e:
                        raise GatewayValidationError(f"Post-Validation failed: {str(e)}",[])

                # NEW: For FastAPI pre-validated models, update the original parameter
                if validated_model is not None:
                    # Find the original parameter name and update it
                    for key, value in kwargs.items():
                        if isinstance(value, BaseModel) and type(value) == type(validated):
                            kwargs[key] = validated
                            break
                else:
                    # Raw mode - inject validated parameter
                    if 'validated' not in kwargs:
                        kwargs['validated'] = validated

                return await func(*args, **kwargs)
            
            except ValidationError as e:
                formatter = error_formatter or default_error_formatter
                details = formatter(e.errors())
                error = GatewayValidationError("Validation Failed", details)
                return adapter.handle_validation_error(error)

            except GatewayValidationError as e:
                return adapter.handle_validation_error(e)
        @wraps(func)
        def sync_wrapper(*args, **kwargs):
            try:
                request_data = adapter.extract_request_data(*args, **kwargs)

                validated_model = None
                if isinstance(request_data, tuple) and len(request_data) == 2:
                    request_data, validated_model = request_data

                if validated_model is None:
                    for pre_validator in pre_validators:
                        request_data = pre_validator(request_data)

                    validated = model.model_validate(
                        request_data,
                        strict=(mode == ValidationMode.STRICT),
                    )
                else:
                    validated = validated_model

                for post_validator in post_validators:
                    try:
                        validated = post_validator(validated)
                    except Exception as e:
                        raise GatewayValidationError(f"Post-Validation failed: {str(e)}",[])

                if validated_model is not None:
                    for key, value in list(kwargs.items()):
                        if isinstance(value, BaseModel) and isinstance(value, model):
                            kwargs[key] = validated
                            break
                else:
                    if 'validated' not in kwargs:
                        kwargs['validated'] = validated

                return func(*args, **kwargs)
                
            except ValidationError as e:
                formatter = error_formatter or default_error_formatter
                details = formatter(e.errors())
                error = GatewayValidationError("Validation Failed", details)
                return adapter.handle_validation_error(error)
                
            except GatewayValidationError as e:
                return adapter.handle_validation_error(e)
                
        return async_wrapper if is_async else sync_wrapper
    return decorator

# Convenience functions for different frameworks
def validate_flask(model: type[BaseModel],mode: Optional[ValidationMode] = ValidationMode.STRICT, **kwargs):
    """Convenience function for Flask"""
    return validate_request(model, adapter=FlaskAdapter(), mode=mode,**kwargs)

def validate_django(model: type[BaseModel], mode: Optional[ValidationMode] = ValidationMode.STRICT, **kwargs):
    """Convenience function for Django"""
    return validate_request(model, adapter=DjangoAdapter(),mode=mode, **kwargs)

def validate_fastapi(model: type[BaseModel],mode: Optional[ValidationMode] = ValidationMode.STRICT, **kwargs):
    """Convenience function for FastAPI"""
    return validate_request(model, adapter=FastAPIAdapter(),mode=mode, **kwargs)

def validate_generic(model: type[BaseModel],mode: Optional[ValidationMode] = ValidationMode.STRICT, **kwargs):
    """Convenience function for generic/custom frameworks"""
    return validate_request(model, adapter=GenericAdapter(),mode=mode, **kwargs)

# Common pre-validator examples
class PreValidators:
    """Common pre-validation functions"""
    
    @staticmethod
    def normalize_email(data: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize email field to lowercase"""
        if 'email' in data and isinstance(data['email'], str):
            data['email'] = data['email'].lower().strip()
        return data
    
    @staticmethod
    def sanitize_strings(data: Dict[str, Any]) -> Dict[str, Any]:
        """Strip whitespace from all string fields"""
        def clean_value(value):
            if isinstance(value, str):
                return value.strip()
            elif isinstance(value, dict):
                return {k: clean_value(v) for k, v in value.items()}
            elif isinstance(value, list):
                return [clean_value(item) for item in value]
            return value
        
        return clean_value(data)
    
    @staticmethod
    def remove_null_fields(data: Dict[str, Any]) -> Dict[str, Any]:
        """Remove fields with None values"""
        return {k: v for k, v in data.items() if v is not None}
    
    @staticmethod
    def normalize_phone(data: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize phone numbers by removing common separators"""
        if 'phone' in data and isinstance(data['phone'], str):
            data['phone'] = ''.join(char for char in data['phone'] if char.isdigit())
        return data
    
    @staticmethod
    def convert_to_lowercase(fields: List[str]):
        """Factory function to create a validator that converts specified fields to lowercase"""
        def validator(data: Dict[str, Any]) -> Dict[str, Any]:
            for field in fields:
                if field in data and isinstance(data[field], str):
                    data[field] = data[field].lower()
            return data
        return validator

# Note: No common post-validators provided - those are your business logic!

# Usage Examples:
"""
# Basic usage:
@validate_flask(UserModel)
def create_user():
    # Flask request data is automatically extracted and validated
    pass

# With built-in pre-validators only (no post-validators provided by framework):
@validate_flask(
    UserModel, 
    pre_validators=[
        PreValidators.normalize_email, 
        PreValidators.sanitize_strings,
        PreValidators.convert_to_lowercase(['username', 'department'])
    ]
)
def create_user():
    pass

# With custom validators (your business logic):
def validate_user_permissions(data: Dict[str, Any]) -> Dict[str, Any]:
    \"\"\"Custom pre-validator: Check user has required permissions\"\"\"
    if data.get('role') == 'admin' and not data.get('department'):
        raise ValueError("Admin users must specify a department")
    return data

def enforce_business_rules(validated: UserModel) -> UserModel:
    \"\"\"Custom post-validator: Apply your business rules\"\"\"
    if validated.role == 'admin' and validated.salary < 100000:
        raise ValueError("Admin salary must be at least $100,000")
    return validated

def audit_user_creation(validated: UserModel) -> UserModel:
    \"\"\"Custom post-validator: Log for audit trail\"\"\"
    logger.info(f"Creating user: {validated.username} with role: {validated.role}")
    return validated

@validate_django(
    UserModel,
    pre_validators=[validate_user_permissions, PreValidators.normalize_email],
    post_validators=[enforce_business_rules, audit_user_creation]
)
def update_user(request):
    # Your function gets clean, validated, business-rule-checked data
    pass

# Complex validation pipeline:
def check_duplicate_email(data: Dict[str, Any]) -> Dict[str, Any]:
    \"\"\"Check if email already exists in database\"\"\"
    if 'email' in data:
        if User.objects.filter(email=data['email']).exists():
            raise ValueError("Email already exists")
    return data

def log_sensitive_operations(validated: UserModel) -> UserModel:
    \"\"\"Log sensitive user operations for security\"\"\"
    if validated.role in ['admin', 'moderator']:
        SecurityLog.create(
            action='user_creation',
            user_data=validated.model_dump(exclude={'password'})
        )
    return validated

@validate_fastapi(
    UserModel,
    pre_validators=[
        PreValidators.sanitize_strings,
        PreValidators.normalize_email,
        check_duplicate_email
    ],
    post_validators=[log_sensitive_operations]
)
def create_admin_user(data: dict):
    # All validation, business rules, and logging handled by the decorator
    # Function just focuses on the core logic
    pass

# Custom adapter for a custom framework:
class MyFrameworkAdapter(FrameworkAdapter):
    def extract_request_data(self, custom_request, *args, **kwargs):
        return custom_request.get_json_data()
    
    def handle_validation_error(self, error):
        return {"status": "error", "message": error.message, "details": error.details}

@validate_request(
    UserModel, 
    adapter=MyFrameworkAdapter(),
    pre_validators=[PreValidators.normalize_email],
    post_validators=[my_custom_business_logic]
)
def process_request(request_obj):
    pass
"""