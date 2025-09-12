"""
Comprehensive test suite for the RBAC-only authentication and authorization system.
Tests every component, edge case, and security scenario.
"""
import pytest
import json
import base64
import time
from unittest.mock import Mock, patch
from datetime import datetime, timedelta

from apigateway.core.auth.auth import (
    authorize_request, authorize_flask, authorize_django, authorize_fastapi, authorize_generic,
    decode_token_payload, has_required_roles
)
from apigateway.exceptions.AuthError import (
    AuthError, AuthenticationError, AuthorizationError, TokenError
)


class TestTokenPayloadDecoding:
    """Test JWT payload decoding without verification"""
    
    def setup_method(self):
        """Setup for each test"""
        # Valid payload
        self.payload = {
            "sub": "user123",
            "username": "testuser", 
            "email": "test@example.com",
            "roles": ["user", "admin"],
            "permissions": ["read", "write"],
            "exp": int(time.time()) + 3600,  # Expires in 1 hour (ignored)
            "iat": int(time.time())
        }
        
        # Create token manually (just for payload structure)
        self.valid_token = self._create_test_token(self.payload)
    
    def _create_test_token(self, payload):
        """Create test JWT token with proper structure"""
        import json
        import base64
        
        # Header (doesn't matter for our RBAC-only approach)
        header = {"typ": "JWT", "alg": "HS256"}
        
        # Encode header and payload
        header_encoded = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
        payload_encoded = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
        
        # Fake signature (doesn't matter since we don't verify)
        signature = "fake_signature_here"
        
        return f"{header_encoded}.{payload_encoded}.{signature}"
    
    def test_decode_valid_token_payload_success(self):
        """Test decoding valid token payload returns correct user data"""
        user_data = decode_token_payload(self.valid_token)
        
        assert user_data['user_id'] == "user123"
        assert user_data['username'] == "testuser"
        assert user_data['email'] == "test@example.com"
        assert user_data['roles'] == ["user", "admin"]
        assert user_data['permissions'] == ["read", "write"]
        assert user_data['token_payload']['sub'] == "user123"
    
    def test_decode_token_minimal_payload(self):
        """Test decoding token with minimal payload"""
        minimal_payload = {
            "sub": "user456",
            "exp": int(time.time()) + 3600  # This will be ignored
        }
        token = self._create_test_token(minimal_payload)
        
        user_data = decode_token_payload(token)
        
        assert user_data['user_id'] == "user456"
        assert user_data['username'] is None
        assert user_data['email'] is None
        assert user_data['roles'] == []
        assert user_data['permissions'] == []
    
    def test_decode_token_with_expired_payload(self):
        """Test that expired payload is decoded anyway (no verification)"""
        expired_payload = {
            "sub": "user123",
            "exp": int(time.time()) - 3600,  # Expired 1 hour ago (ignored)
            "iat": int(time.time()) - 7200   # Issued 2 hours ago (ignored)
        }
        token = self._create_test_token(expired_payload)
        
        # Should succeed because we don't verify expiration
        user_data = decode_token_payload(token)
        assert user_data['user_id'] == "user123"
    
    def test_decode_token_malformed_token_raises_error(self):
        """Test that malformed tokens raise TokenError"""
        malformed_tokens = [
            "not.a.jwt",
            "malformed",
            "",
            None,
            "only.two.parts",
            "one",
            "too.many.parts.here.extra"
        ]
        
        for bad_token in malformed_tokens:
            with pytest.raises(TokenError):
                decode_token_payload(bad_token)
    
    def test_decode_token_invalid_base64_raises_error(self):
        """Test that invalid base64 payload raises TokenError"""
        # Create token with invalid base64 payload
        header = base64.urlsafe_b64encode(json.dumps({"typ": "JWT"}).encode()).decode().rstrip('=')
        invalid_payload = "invalid_base64_here!"
        signature = "fake_sig"
        
        bad_token = f"{header}.{invalid_payload}.{signature}"
        
        with pytest.raises(TokenError, match="Failed to decode token payload"):
            decode_token_payload(bad_token)
    
    def test_decode_token_invalid_json_raises_error(self):
        """Test that invalid JSON in payload raises TokenError"""
        # Create token with invalid JSON payload
        header = base64.urlsafe_b64encode(json.dumps({"typ": "JWT"}).encode()).decode().rstrip('=')
        invalid_json = base64.urlsafe_b64encode(b'{"invalid": json}').decode().rstrip('=')
        signature = "fake_sig"
        
        bad_token = f"{header}.{invalid_json}.{signature}"
        
        with pytest.raises(TokenError, match="Failed to decode token payload"):
            decode_token_payload(bad_token)


class TestRoleValidation:
    """Test role-based authorization logic"""
    
    def test_has_required_roles_single_role_match(self):
        """Test role checking with single matching role"""
        user_roles = ["user", "admin", "moderator"]
        required_roles = ["admin"]
        
        assert has_required_roles(user_roles, required_roles) is True
    
    def test_has_required_roles_multiple_roles_one_match(self):
        """Test role checking with multiple required roles, one match"""
        user_roles = ["user", "moderator"]
        required_roles = ["admin", "moderator", "superuser"]
        
        assert has_required_roles(user_roles, required_roles) is True
    
    def test_has_required_roles_no_match(self):
        """Test role checking with no matching roles"""
        user_roles = ["user"]
        required_roles = ["admin", "moderator"]
        
        assert has_required_roles(user_roles, required_roles) is False
    
    def test_has_required_roles_empty_user_roles(self):
        """Test role checking with empty user roles"""
        user_roles = []
        required_roles = ["admin"]
        
        assert has_required_roles(user_roles, required_roles) is False
    
    def test_has_required_roles_empty_required_roles(self):
        """Test role checking with empty required roles"""
        user_roles = ["user", "admin"]
        required_roles = []
        
        assert has_required_roles(user_roles, required_roles) is False
    
    def test_has_required_roles_case_sensitive(self):
        """Test that role checking is case-sensitive"""
        user_roles = ["admin"]
        required_roles = ["ADMIN"]  # Different case
        
        assert has_required_roles(user_roles, required_roles) is False
    
    def test_has_required_roles_none_values(self):
        """Test role validation handles None values gracefully"""
        # Test None user roles
        assert has_required_roles(None, ["admin"]) is False
        
        # Test None required roles  
        assert has_required_roles(["user"], None) is False
        
        # Test both None
        assert has_required_roles(None, None) is False


class TestAuthorizationDecorator:
    """Test the authorization decorator functionality"""
    
    def setup_method(self):
        """Setup for each test"""
        # Create test tokens with different roles
        self.admin_payload = {
            "sub": "user123",
            "username": "testuser",
            "roles": ["user", "admin"],
            "exp": int(time.time()) + 3600
        }
        self.admin_token = self._create_test_token(self.admin_payload)
        
        self.basic_payload = {
            "sub": "user456", 
            "username": "basicuser",
            "roles": ["user"],
            "exp": int(time.time()) + 3600
        }
        self.basic_user_token = self._create_test_token(self.basic_payload)
    
    def _create_test_token(self, payload):
        """Create test JWT token with proper structure"""
        header = {"typ": "JWT", "alg": "HS256"}
        
        header_encoded = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
        payload_encoded = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
        signature = "fake_signature"
        
        return f"{header_encoded}.{payload_encoded}.{signature}"
    
    def test_authorize_generic_no_roles_required_success(self):
        """Test authorization with no roles required (just token presence)"""
        # Mock adapter that returns our token
        mock_adapter = Mock()
        mock_adapter.extract_auth_token.return_value = self.admin_token
        
        @authorize_request(required_roles=None, adapter=mock_adapter)  
        def test_function(user=None):
            return {"status": "success"}
        
        result = test_function()
        assert result == {"status": "success"}
    
    def test_authorize_generic_with_required_roles_success(self):
        """Test authorization with required roles - success case"""
        mock_adapter = Mock()
        mock_adapter.extract_auth_token.return_value = self.admin_token
        
        @authorize_request(required_roles=["admin"], adapter=mock_adapter)
        def admin_function(user):
            return {"admin": user['username']}
        
        result = admin_function()
        assert result == {"admin": "testuser"}
    
    def test_authorize_generic_insufficient_roles_fails(self):
        """Test authorization fails when user lacks required roles"""
        mock_adapter = Mock()
        mock_adapter.extract_auth_token.return_value = self.basic_user_token  # Only has 'user' role
        mock_adapter.handle_auth_error.return_value = {"error": "Access denied"}
        
        @authorize_request(required_roles=["admin"], adapter=mock_adapter)
        def admin_function():
            return {"status": "success"}
        
        result = admin_function()
        assert result == {"error": "Access denied"}
        mock_adapter.handle_auth_error.assert_called_once()
    
    def test_authorize_generic_no_token_fails(self):
        """Test authorization fails when no token provided"""
        mock_adapter = Mock()
        mock_adapter.extract_auth_token.return_value = None
        mock_adapter.handle_auth_error.return_value = {"error": "No token"}
        
        @authorize_request(required_roles=["user"], adapter=mock_adapter)
        def protected_function():
            return {"status": "success"}
        
        result = protected_function()
        assert result == {"error": "No token"}
        mock_adapter.handle_auth_error.assert_called_once()
    
    def test_authorize_generic_invalid_token_fails(self):
        """Test authorization fails with invalid token"""
        mock_adapter = Mock()
        mock_adapter.extract_auth_token.return_value = "invalid.token.here"
        mock_adapter.handle_auth_error.return_value = {"error": "Invalid token"}
        
        @authorize_request(required_roles=["user"], adapter=mock_adapter)
        def protected_function():
            return {"status": "success"}
        
        result = protected_function()
        assert result == {"error": "Invalid token"}
        mock_adapter.handle_auth_error.assert_called_once()
    
    def test_authorize_generic_user_injection(self):
        """Test that user data is properly injected into kwargs"""
        mock_adapter = Mock()
        mock_adapter.extract_auth_token.return_value = self.admin_token
        
        @authorize_request(required_roles=["user"], adapter=mock_adapter)
        def test_function(user):
            return {
                "user_id": user['user_id'],
                "username": user['username'],
                "roles": user['roles']
            }
        
        result = test_function()
        assert result == {
            "user_id": "user123",
            "username": "testuser", 
            "roles": ["user", "admin"]
        }
    
    def test_authorize_generic_multiple_required_roles(self):
        """Test authorization with multiple required roles (OR logic)"""
        mock_adapter = Mock()
        mock_adapter.extract_auth_token.return_value = self.basic_user_token  # Has 'user' role
        
        @authorize_request(required_roles=["admin", "user", "moderator"], adapter=mock_adapter)
        def multi_role_function(user):
            return {"allowed": True, "user": user['username']}
        
        result = multi_role_function()
        assert result == {"allowed": True, "user": "basicuser"}
    
    def test_decorator_with_existing_user_kwarg(self):
        """Test decorator doesn't override existing 'user' parameter"""
        mock_adapter = Mock()
        mock_adapter.extract_auth_token.return_value = self.admin_token
        
        @authorize_request(required_roles=["user"], adapter=mock_adapter)
        def test_function(user="existing_user"):
            return {"user": user}
        
        # Call with existing user parameter
        result = test_function(user="passed_user")
        
        # Should keep the passed user, not inject token user
        assert result == {"user": "passed_user"}


class TestAsyncAuthorization:
    """Test async function authorization"""
    
    def setup_method(self):
        """Setup for async tests"""
        payload = {
            "sub": "async_user",
            "username": "asynctest",
            "roles": ["user"],
            "exp": int(time.time()) + 3600
        }
        self.async_token = self._create_test_token(payload)
    
    def _create_test_token(self, payload):
        """Create test JWT token"""
        header = {"typ": "JWT", "alg": "HS256"}
        header_encoded = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
        payload_encoded = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
        return f"{header_encoded}.{payload_encoded}.fake_sig"
    
    @pytest.mark.asyncio
    async def test_authorize_async_function_success(self):
        """Test authorization decorator works with async functions"""
        mock_adapter = Mock()
        mock_adapter.extract_auth_token.return_value = self.async_token
        
        @authorize_request(required_roles=["user"], adapter=mock_adapter)
        async def async_function(user):
            return {"async": True, "user": user['username']}
        
        result = await async_function()
        assert result == {"async": True, "user": "asynctest"}
    
    @pytest.mark.asyncio
    async def test_authorize_async_function_auth_failure(self):
        """Test async authorization failure handling"""
        mock_adapter = Mock()
        mock_adapter.extract_auth_token.return_value = None
        mock_adapter.handle_auth_error.return_value = {"error": "Async auth failed"}
        
        @authorize_request(required_roles=["user"], adapter=mock_adapter)
        async def async_function():
            return {"status": "success"}
        
        result = await async_function()
        assert result == {"error": "Async auth failed"}


class TestFrameworkConvenienceFunctions:
    """Test framework-specific convenience functions"""
    
    def test_authorize_flask_creates_flask_adapter(self):
        """Test that authorize_flask uses FlaskAdapter"""
        with patch('apigateway.core.auth.auth.authorize_request') as mock_authorize:
            mock_authorize.return_value = lambda f: f  # Return function unchanged
            
            @authorize_flask(["admin"])
            def flask_endpoint():
                return {"framework": "flask"}
            
            # Check that authorize_request was called with FlaskAdapter
            mock_authorize.assert_called_once()
            args, kwargs = mock_authorize.call_args
            
            assert args[0] == ["admin"]  # required_roles
            from apigateway.core.adapters.flask import FlaskAdapter
            assert isinstance(kwargs['adapter'], FlaskAdapter)
    
    def test_authorize_django_creates_django_adapter(self):
        """Test that authorize_django uses DjangoAdapter"""
        with patch('apigateway.core.auth.auth.authorize_request') as mock_authorize:
            mock_authorize.return_value = lambda f: f
            
            @authorize_django(["moderator"])
            def django_view():
                return {"framework": "django"}
            
            mock_authorize.assert_called_once()
            args, kwargs = mock_authorize.call_args
            
            assert args[0] == ["moderator"]
            from apigateway.core.adapters.django import DjangoAdapter
            assert isinstance(kwargs['adapter'], DjangoAdapter)
    
    def test_authorize_fastapi_creates_fastapi_adapter(self):
        """Test that authorize_fastapi uses FastAPIAdapter"""
        with patch('apigateway.core.auth.auth.authorize_request') as mock_authorize:
            mock_authorize.return_value = lambda f: f
            
            @authorize_fastapi(["user"])
            def fastapi_endpoint():
                return {"framework": "fastapi"}
            
            mock_authorize.assert_called_once()
            args, kwargs = mock_authorize.call_args
            
            assert args[0] == ["user"]
            from apigateway.core.adapters.fastapi import FastAPIAdapter
            assert isinstance(kwargs['adapter'], FastAPIAdapter)


class TestSecurityScenarios:
    """Test various security scenarios for RBAC"""
    
    def test_token_payload_tampering_allowed(self):
        """Test that payload tampering is allowed since we don't verify signatures"""
        # Create token with user role
        original_payload = {"sub": "user123", "roles": ["user"]}
        
        # Manually create tampered token with admin role
        tampered_payload = {"sub": "user123", "roles": ["admin"]}
        
        header = {"typ": "JWT", "alg": "HS256"}
        header_encoded = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
        payload_encoded = base64.urlsafe_b64encode(json.dumps(tampered_payload).encode()).decode().rstrip('=')
        tampered_token = f"{header_encoded}.{payload_encoded}.fake_sig"
        
        # Should succeed because we don't verify signatures - this is by design!
        user_data = decode_token_payload(tampered_token)
        assert user_data['roles'] == ["admin"]  # Tampered role is accepted
    
    def test_role_escalation_in_payload(self):
        """Test that role escalation in payload works (no verification)"""
        # This demonstrates why this approach requires trusted upstream auth
        payload = {"sub": "attacker", "roles": ["admin", "superuser", "god_mode"]}
        
        header = {"typ": "JWT", "alg": "HS256"}
        header_encoded = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
        payload_encoded = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
        malicious_token = f"{header_encoded}.{payload_encoded}.fake_sig"
        
        # This will work because we trust the payload
        user_data = decode_token_payload(malicious_token)
        assert "admin" in user_data['roles']
        assert "superuser" in user_data['roles']
        assert "god_mode" in user_data['roles']
        
        # This is why upstream authentication MUST be trusted!


class TestErrorHandling:
    """Test comprehensive error handling"""
    
    def test_auth_error_hierarchy(self):
        """Test that error classes have proper inheritance"""
        auth_error = AuthError("Test error")
        assert isinstance(auth_error, Exception)
        
        auth_error = AuthenticationError("Auth required")
        assert isinstance(auth_error, AuthError)
        
        authz_error = AuthorizationError("Access denied")
        assert isinstance(authz_error, AuthError)
        
        token_error = TokenError("Invalid token")
        assert isinstance(token_error, AuthError)
    
    def test_auth_error_serialization(self):
        """Test that auth errors serialize properly"""
        error = AuthenticationError("Token required", [{"field": "token", "message": "missing"}])
        
        assert error.message == "Token required"
        assert error.code == "authentication_required"
        assert error.details == [{"field": "token", "message": "missing"}]
        
        # Test string representation
        error_str = str(error)
        assert "AUTHENTICATION_REQUIRED" in error_str
        assert "Token required" in error_str


class TestEdgeCases:
    """Test edge cases and boundary conditions"""
    
    def test_token_with_unicode_characters(self):
        """Test token handling with unicode characters"""
        payload = {
            "sub": "user123",
            "username": "用户",  # Chinese characters
            "email": "test@münchen.de",  # German umlaut
            "roles": ["ユーザー"],  # Japanese characters
            "exp": int(time.time()) + 3600
        }
        
        header = {"typ": "JWT", "alg": "HS256"}
        header_encoded = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
        payload_encoded = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
        token = f"{header_encoded}.{payload_encoded}.fake_sig"
        
        user_data = decode_token_payload(token)
        assert user_data['username'] == "用户"
        assert user_data['email'] == "test@münchen.de"
        assert user_data['roles'] == ["ユーザー"]
    
    def test_token_with_very_large_payload(self):
        """Test token with large payload (near size limits)"""
        # Create large role list
        large_roles = [f"role_{i}" for i in range(1000)]
        
        payload = {
            "sub": "user123",
            "roles": large_roles,
            "exp": int(time.time()) + 3600
        }
        
        header = {"typ": "JWT", "alg": "HS256"}
        header_encoded = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
        payload_encoded = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
        token = f"{header_encoded}.{payload_encoded}.fake_sig"
        
        user_data = decode_token_payload(token)
        assert len(user_data['roles']) == 1000
        assert "role_999" in user_data['roles']
    
    def test_empty_roles_in_payload(self):
        """Test token with empty roles"""
        payload = {
            "sub": "user123",
            "roles": [],  # Empty roles
            "exp": int(time.time()) + 3600
        }
        
        header = {"typ": "JWT", "alg": "HS256"}
        header_encoded = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
        payload_encoded = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
        token = f"{header_encoded}.{payload_encoded}.fake_sig"
        
        user_data = decode_token_payload(token)
        assert user_data['roles'] == []
        
        # Should fail role check
        assert has_required_roles(user_data['roles'], ["admin"]) is False
    
    def test_missing_roles_field_in_payload(self):
        """Test token without roles field"""
        payload = {
            "sub": "user123",
            "username": "testuser",
            # No roles field
            "exp": int(time.time()) + 3600
        }
        
        header = {"typ": "JWT", "alg": "HS256"}
        header_encoded = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
        payload_encoded = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
        token = f"{header_encoded}.{payload_encoded}.fake_sig"
        
        user_data = decode_token_payload(token)
        assert user_data['roles'] == []  # Should default to empty list
        
        # Should fail role check
        assert has_required_roles(user_data['roles'], ["admin"]) is False


class TestIntegrationScenarios:
    """Test realistic integration scenarios"""
    
    def test_microservice_rbac_flow(self):
        """Test typical microservice RBAC flow"""
        # Simulate token that came from API Gateway (already authenticated)
        gateway_token_payload = {
            "sub": "authenticated_user_123",
            "username": "service_user",
            "roles": ["service_reader", "data_processor"],
            "service": "payment_processor",
            "exp": int(time.time()) + 3600  # Ignored
        }
        
        header = {"typ": "JWT", "alg": "HS256"}
        header_encoded = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
        payload_encoded = base64.urlsafe_b64encode(json.dumps(gateway_token_payload).encode()).decode().rstrip('=')
        token = f"{header_encoded}.{payload_encoded}.trusted_gateway_signature"
        
        # Mock adapter
        mock_adapter = Mock()
        mock_adapter.extract_auth_token.return_value = token
        
        # Service endpoint that requires data_processor role
        @authorize_request(required_roles=["data_processor"], adapter=mock_adapter)
        def process_payment_data(user):
            return {
                "processed": True,
                "processor": user['username'],
                "service": user['token_payload'].get('service')
            }
        
        result = process_payment_data()
        assert result["processed"] is True
        assert result["processor"] == "service_user"
        assert result["service"] == "payment_processor"
    
    def test_multi_role_service_access(self):
        """Test service with multiple role requirements"""
        # User with mixed roles
        user_payload = {
            "sub": "user_456",
            "username": "admin_user",
            "roles": ["user", "admin", "auditor"],
            "department": "security"
        }
        
        header = {"typ": "JWT", "alg": "HS256"}
        header_encoded = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
        payload_encoded = base64.urlsafe_b64encode(json.dumps(user_payload).encode()).decode().rstrip('=')
        token = f"{header_encoded}.{payload_encoded}.sig"
        
        mock_adapter = Mock()
        mock_adapter.extract_auth_token.return_value = token
        
        # Endpoint requiring admin OR auditor role
        @authorize_request(required_roles=["admin", "auditor"], adapter=mock_adapter)
        def sensitive_operation(user):
            return {"access_granted": True, "user_roles": user['roles']}
        
        result = sensitive_operation()
        assert result["access_granted"] is True
        assert "admin" in result["user_roles"]
        assert "auditor" in result["user_roles"]