from functools import wraps
import inspect
from typing import Callable, Dict, Any, List, Optional, Union
from dataclasses import dataclass, field
from apigateway.core.adapters.base_adapter import FrameworkAdapter
from apigateway.core.adapters.django import DjangoAdapter
from apigateway.core.adapters.fastapi import FastAPIAdapter
from apigateway.core.adapters.flask import FlaskAdapter
from apigateway.core.adapters.generic import GenericAdapter
from apigateway.exceptions.GatewayValidationError import GatewayValidationError


@dataclass
class FileConstraints:
    """File upload constraints"""
    max_size: str = "10MB"  # e.g., "10MB", "1GB", "500KB"
    allowed_types: List[str] = field(default_factory=lambda: [
        "image/jpeg", "image/png", "image/gif", 
        "application/pdf", "text/plain", "application/json"
    ])
    max_files: int = 10
    required_files: List[str] = field(default_factory=list)  # Required file field names
    virus_scan: bool = False
    custom_validators: List[Callable] = field(default_factory=list)


class FileValidator:
    """File validation logic"""
    
    def __init__(self, constraints: FileConstraints):
        self.constraints = constraints
        self.max_size_bytes = self._parse_size(constraints.max_size)
    
    def validate_files(self, files: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Validate files and return list of errors.
        Empty list means all files are valid.
        Format matches your existing validation error format.
        """
        errors = []
        
        # Check required files
        for required_field in self.constraints.required_files:
            if required_field not in files or not files[required_field]:
                errors.append({
                    "field": required_field,
                    "message": f"Required file '{required_field}' is missing",
                    "type": "required_file_error"
                })
        
        # Check total file count
        total_files = sum(
            len(file_list) if isinstance(file_list, list) else 1 
            for file_list in files.values() 
            if file_list
        )
        
        if total_files > self.constraints.max_files:
            errors.append({
                "field": "files",
                "message": f"Too many files. Maximum {self.constraints.max_files} allowed, got {total_files}",
                "type": "file_count_error"
            })
            return errors  # Don't process individual files if too many
        
        # Validate individual files
        for field_name, file_obj in files.items():
            if not file_obj:  # Skip empty files
                continue
                
            if isinstance(file_obj, list):
                # Multiple files in same field
                for i, single_file in enumerate(file_obj):
                    file_errors = self._validate_single_file(f"{field_name}[{i}]", single_file)
                    errors.extend(file_errors)
            else:
                # Single file
                file_errors = self._validate_single_file(field_name, file_obj)
                errors.extend(file_errors)
        
        return errors
    
    def _validate_single_file(self, field_name: str, file_obj: Any) -> List[Dict[str, str]]:
        """Validate a single file - framework agnostic"""
        errors = []
        
        try:
            # Extract file info (works with Flask, Django, FastAPI file objects)
            filename = self._get_filename(file_obj)
            content_type = self._get_content_type(file_obj)
            size = self._get_file_size(file_obj)
            
            # Size validation
            if size > self.max_size_bytes:
                errors.append({
                    "field": field_name,
                    "message": f"File '{filename}' is too large. Maximum size is {self.constraints.max_size}",
                    "type": "file_size_error"
                })
            
            # MIME type validation
            if content_type not in self.constraints.allowed_types:
                errors.append({
                    "field": field_name,
                    "message": f"File type '{content_type}' not allowed. Allowed types: {', '.join(self.constraints.allowed_types)}",
                    "type": "file_type_error"
                })
            
            # Filename validation (basic security)
            if not self._is_safe_filename(filename):
                errors.append({
                    "field": field_name,
                    "message": f"Unsafe filename '{filename}'. Avoid special characters and path traversal.",
                    "type": "filename_error"
                })
            
            # Custom validators
            for validator in self.constraints.custom_validators:
                try:
                    validator_result = validator(file_obj, filename, content_type, size)
                    if validator_result is not True:
                        # Validator returned error message
                        errors.append({
                            "field": field_name,
                            "message": str(validator_result),
                            "type": "custom_validation_error"
                        })
                except Exception as e:
                    errors.append({
                        "field": field_name,
                        "message": f"Custom validation failed: {str(e)}",
                        "type": "custom_validation_error"
                    })
        
        except Exception as e:
            errors.append({
                "field": field_name,
                "message": f"File processing error: {str(e)}",
                "type": "file_processing_error"
            })
        
        return errors
    
    def _get_filename(self, file_obj: Any) -> str:
        """Extract filename from framework-specific file object"""
        if hasattr(file_obj, 'filename') and file_obj.filename:
            return file_obj.filename
        elif hasattr(file_obj, 'name') and file_obj.name:
            return file_obj.name
        else:
            return "unknown_file"
    
    def _get_content_type(self, file_obj: Any) -> str:
        """Extract content type from framework-specific file object"""
        if hasattr(file_obj, 'content_type') and file_obj.content_type:
            return file_obj.content_type
        elif hasattr(file_obj, 'content_type') and file_obj.content_type:
            return file_obj.content_type
        else:
            # Fallback: guess from filename
            import mimetypes
            filename = self._get_filename(file_obj)
            return mimetypes.guess_type(filename)[0] or "application/octet-stream"
    
    def _get_file_size(self, file_obj: Any) -> int:
        """Get file size from framework-specific file object"""
        if hasattr(file_obj, 'size'):
            return file_obj.size
        elif hasattr(file_obj, 'content_length'):
            return file_obj.content_length
        else:
            # Fallback: read and measure (not ideal for large files)
            try:
                current_pos = file_obj.tell() if hasattr(file_obj, 'tell') else 0
                file_obj.seek(0, 2)  # Seek to end
                size = file_obj.tell()
                file_obj.seek(current_pos)  # Reset position
                return size
            except:
                return 0
    
    def _parse_size(self, size_str: str) -> int:
        """Parse size string like '10MB' to bytes"""
        size_str = size_str.upper().strip()
        
        if size_str.endswith('KB'):
            return int(float(size_str[:-2]) * 1024)
        elif size_str.endswith('MB'):
            return int(float(size_str[:-2]) * 1024 * 1024)
        elif size_str.endswith('GB'):
            return int(float(size_str[:-2]) * 1024 * 1024 * 1024)
        elif size_str.endswith('B'):
            return int(size_str[:-1])
        else:
            # Assume bytes if no unit
            return int(size_str)
    
    def _is_safe_filename(self, filename: str) -> bool:
        """Basic filename security check"""
        if not filename or filename in ['.', '..']:
            return False
        
        # Check for path traversal
        if '..' in filename or '/' in filename or '\\' in filename:
            return False
        
        # Check for suspicious characters
        dangerous_chars = ['<', '>', ':', '"', '|', '?', '*', '\0']
        if any(char in filename for char in dangerous_chars):
            return False
        
        return True


def default_file_error_formatter(errors: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Default file error formatter - matches your existing error format.
    Can be overridden with custom formatters.
    """
    return errors  # File errors are already in the right format


def validate_files(
    constraints: FileConstraints,
    adapter: Optional[FrameworkAdapter] = None,
    error_formatter: Optional[Callable[[List[Dict[str, Any]]], List[Dict[str, Any]]]] = None,
    pre_validators: Optional[List[Callable[[Dict[str, Any]], Dict[str, Any]]]] = None,
    post_validators: Optional[List[Callable[[Dict[str, Any]], Dict[str, Any]]]] = None,
):
    """
    Framework-agnostic file validation decorator.
    Follows the exact same pattern as your validate_request decorator.
    
    Args:
        constraints: FileConstraints object defining validation rules
        adapter: Framework adapter (if None, uses GenericAdapter)
        error_formatter: Custom error formatter function
        pre_validators: List of functions to run on raw files before validation
        post_validators: List of functions to run on files after validation
    
    Pipeline:
        extract_files → pre_validators → file_validation → post_validators → function
    """
    
    # Use GenericAdapter if no adapter specified
    if adapter is None:
        adapter = GenericAdapter()
    
    # Default to empty lists if None
    pre_validators = pre_validators or []
    post_validators = post_validators or []
    
    # Create file validator
    file_validator = FileValidator(constraints)
    
    def decorator(func: Callable):
        is_async = inspect.iscoroutinefunction(func)
        
        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            try:
                # Step 1: Extract files using adapter
                files = adapter.extract_files(*args, **kwargs)
                
                # Step 2: Run pre-validators on raw files
                for pre_validator in pre_validators:
                    files = pre_validator(files)
                
                # Step 3: Validate files
                file_errors = file_validator.validate_files(files)
                if file_errors:
                    formatter = error_formatter or default_file_error_formatter
                    formatted_errors = formatter(file_errors)
                    error = GatewayValidationError("File validation failed", formatted_errors)
                    return adapter.handle_validation_error(error)
                
                # Step 4: Run post-validators on validated files
                for post_validator in post_validators:
                    try:
                        files = post_validator(files)
                    except Exception as e:
                        raise GatewayValidationError(f"File post-validation failed: {str(e)}", [])
                
                # Step 5: Inject validated files into function
                if 'validated_files' not in kwargs:
                    kwargs['validated_files'] = files
                
                return await func(*args, **kwargs)
            
            except GatewayValidationError as e:
                return adapter.handle_validation_error(e)
        
        @wraps(func)
        def sync_wrapper(*args, **kwargs):
            try:
                # Same logic for sync functions
                files = adapter.extract_files(*args, **kwargs)
                
                for pre_validator in pre_validators:
                    files = pre_validator(files)
                
                file_errors = file_validator.validate_files(files)
                if file_errors:
                    formatter = error_formatter or default_file_error_formatter
                    formatted_errors = formatter(file_errors)
                    error = GatewayValidationError("File validation failed", formatted_errors)
                    return adapter.handle_validation_error(error)
                
                for post_validator in post_validators:
                    try:
                        files = post_validator(files)
                    except Exception as e:
                        raise GatewayValidationError(f"File post-validation failed: {str(e)}", [])
                
                if 'validated_files' not in kwargs:
                    kwargs['validated_files'] = files
                
                return func(*args, **kwargs)
                
            except GatewayValidationError as e:
                return adapter.handle_validation_error(e)
        
        return async_wrapper if is_async else sync_wrapper
    return decorator


# Convenience functions for different frameworks (matches your validation.py pattern)
def validate_files_flask(constraints: FileConstraints, **kwargs):
    """Convenience function for Flask file validation"""
    return validate_files(constraints, adapter=FlaskAdapter(), **kwargs)


def validate_files_django(constraints: FileConstraints, **kwargs):
    """Convenience function for Django file validation"""
    return validate_files(constraints, adapter=DjangoAdapter(), **kwargs)


def validate_files_fastapi(constraints: FileConstraints, **kwargs):
    """Convenience function for FastAPI file validation"""
    return validate_files(constraints, adapter=FastAPIAdapter(), **kwargs)


def validate_files_generic(constraints: FileConstraints, **kwargs):
    """Convenience function for generic/custom frameworks"""
    return validate_files(constraints, adapter=GenericAdapter(), **kwargs)


# Common file pre-validator examples (matches your PreValidators pattern)
class FilePreValidators:
    """Common file pre-validation functions"""
    
    @staticmethod
    def remove_empty_files(files: Dict[str, Any]) -> Dict[str, Any]:
        """Remove empty file fields"""
        return {k: v for k, v in files.items() if v}
    
    @staticmethod
    def normalize_filenames(files: Dict[str, Any]) -> Dict[str, Any]:
        """Sanitize filenames by removing special characters"""
        # This is a no-op since we can't modify the actual file objects
        # But you could store sanitized names in metadata
        return files
    
    @staticmethod
    def log_file_uploads(files: Dict[str, Any]) -> Dict[str, Any]:
        """Log file upload attempts"""
        import logging
        logger = logging.getLogger(__name__)
        
        for field_name, file_obj in files.items():
            if file_obj:
                if isinstance(file_obj, list):
                    logger.info(f"File upload: {field_name} - {len(file_obj)} files")
                else:
                    filename = getattr(file_obj, 'filename', 'unknown')
                    logger.info(f"File upload: {field_name} - {filename}")
        
        return files


# Common file post-validator examples
class FilePostValidators:
    """Common file post-validation functions - your business logic goes here"""
    
    @staticmethod
    def save_to_temp_storage(files: Dict[str, Any]) -> Dict[str, Any]:
        """Save uploaded files to temporary storage"""
        import tempfile
        import shutil
        
        saved_paths = {}
        for field_name, file_obj in files.items():
            if file_obj and hasattr(file_obj, 'save'):
                # Flask-style save
                temp_path = tempfile.mktemp()
                file_obj.save(temp_path)
                saved_paths[field_name] = temp_path
            # Add logic for Django, FastAPI file saving
        
        # Store paths in files dict (or return modified structure)
        return files
    
    @staticmethod
    def generate_file_metadata(files: Dict[str, Any]) -> Dict[str, Any]:
        """Generate metadata for uploaded files"""
        # Add metadata, compute hashes, etc.
        # Your business logic here
        return files


# Usage examples (matches your validation.py examples):
"""
# Basic usage:
@validate_files_flask(FileConstraints(max_size="5MB", allowed_types=["image/jpeg", "image/png"]))
def upload_avatar(validated_files):
    avatar = validated_files.get('avatar')
    # Process avatar file
    pass

# With pre/post validators:
@validate_files_flask(
    FileConstraints(
        max_size="10MB",
        allowed_types=["application/pdf", "image/jpeg"],
        required_files=["document"],
        max_files=3
    ),
    pre_validators=[FilePreValidators.remove_empty_files, FilePreValidators.log_file_uploads],
    post_validators=[FilePostValidators.save_to_temp_storage]
)
def upload_documents(validated_files):
    # Files are validated, logged, and saved to temp storage
    pass

# Combined with your existing validation:
from apigateway.core.validation import validate_flask

class UserSchema(BaseModel):
    username: str
    age: int

@validate_flask(UserSchema)
@validate_files_flask(FileConstraints(max_size="2MB", allowed_types=["image/jpeg"]))
def create_user_with_avatar(validated, validated_files):
    # Both data and files are validated
    username = validated.username
    avatar = validated_files.get('avatar')
    pass

# Custom file validation:
def validate_image_dimensions(file_obj, filename, content_type, size):
    if content_type.startswith('image/'):
        # Check image dimensions using PIL
        from PIL import Image
        img = Image.open(file_obj)
        if img.width > 2000 or img.height > 2000:
            return "Image dimensions too large (max 2000x2000)"
        file_obj.seek(0)  # Reset file pointer
    return True

@validate_files_flask(FileConstraints(
    max_size="5MB",
    custom_validators=[validate_image_dimensions]
))
def upload_profile_picture(validated_files):
    pass
"""