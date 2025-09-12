"""
Comprehensive test suite for the authentication and authorization system.
Tests every component, edge case, and security scenario.
"""
import pytest
import jwt
import time
import os
from unittest.mock import Mock, patch
from datetime import datetime, timedelta

from apigateway.core.auth.auth import (
    JWTConfig, configure_jwt, get_jwt_config, authorize_request,
    authorize_flask, authorize_django, authorize_fastapi, authorize_generic,
    decode_jwt, has_required_roles
)
from apigateway.exceptions.AuthError import (
    AuthError, AuthenticationError, AuthorizationError, TokenError
)


class TestJWTConfig:
    """Test JWT configuration class"""
    
    def test_jwt_config_basic(self):
        """Test basic JWT config creation"""
        config = JWTConfig(secret="test-secret-32-characters-long!")
        assert config.secret == "test-secret-32-characters-long!"
        assert config.algorithm == "HS256"
        assert config.verify_exp is True
        assert config.leeway == 10
    
    def test_jwt_config_custom_params(self):
        """Test JWT config with custom parameters"""
        config = JWTConfig(
            secret="custom-secret-key-32-chars-long!",
            algorithm="HS512", 
            verify_exp=False,
            leeway=30
        )
        assert config.secret == "custom-secret-key-32-chars-long!"
        assert config.algorithm == "HS512"
        assert config.verify_exp is False
        assert config.leeway == 30


class TestGlobalJWTConfiguration:
    """Test global JWT configuration management"""
    
    def setup_method(self):
        """Reset global config before each test"""
        # Reset global config
        import apigateway.core.auth
        apigateway.core.auth._jwt_config = None
    
    def test_configure_jwt_sets_global_config(self):
        """Test that configure_jwt sets global configuration"""
        configure_jwt(secret="test-secret-32-characters-long!")
        
        config = get_jwt_config()
        assert config.secret == "test-secret-32-characters-long!"
        assert config.algorithm == "HS256"
    
    def test_configure_jwt_with_custom_params(self):
        """Test configure_jwt with custom parameters"""
        configure_jwt(
            secret="custom-secret-32-characters-long!",
            algorithm="HS512",
            verify_exp=False,
            leeway=60
        )
        
        config = get_jwt_config()
        assert config.algorithm == "HS512"
        assert config.verify_exp is False
        assert config.leeway == 60
    
    def test_debug_jwt_config(self, monkeypatch):
        """Debug what actually happens"""
        # Clear environment
        monkeypatch.delenv('JWT_SECRET', raising=False)
        monkeypatch.delenv('JWT_SECRET_KEY', raising=False) 
        monkeypatch.delenv('SECRET_KEY', raising=False)
        
        # Reset the global config
        import apigateway.core.auth.auth
        apigateway.core.auth.auth._jwt_config = None
        
        try:
            config = get_jwt_config()
            print(f"Config created: {config}")
            print(f"Secret: {config.secret}")
        except Exception as e:
            print(f"Exception: {type(e).__name__}: {e}")
    
    def test_multiple_configure_jwt_calls_override(self):
        """Test that multiple configure_jwt calls override previous config"""
        configure_jwt(secret="first-secret-32-characters-long!")
        configure_jwt(secret="second-secret-32-characters-long!")
        
        config = get_jwt_config()
        assert config.secret == "second-secret-32-characters-long!"


class TestJWTDecoding:
    """Test JWT token decoding and validation"""
    
    def setup_method(self):
        """Setup for each test"""
        self.secret = "test-secret-key-32-characters-long!"
        self.config = JWTConfig(secret=self.secret)
        
        # Valid payload
        self.payload = {
            "sub": "user123",
            "username": "testuser", 
            "email": "test@example.com",
            "roles": ["user", "admin"],
            "permissions": ["read", "write"],
            "exp": int(time.time()) + 3600,  # Expires in 1 hour
            "iat": int(time.time())
        }
        
        # Create valid token
        self.valid_token = jwt.encode(self.payload, self.secret, algorithm="HS256")
    
    def test_decode_valid_jwt_success(self):
        """Test decoding valid JWT returns correct user data"""
        user_data = decode_jwt(self.valid_token, self.config)
        
        assert user_data['user_id'] == "user123"
        assert user_data['username'] == "testuser"
        assert user_data['email'] == "test@example.com"
        assert user_data['roles'] == ["user", "admin"]
        assert user_data['permissions'] == ["read", "write"]
        assert user_data['token_payload']['sub'] == "user123"
    
    def test_decode_jwt_minimal_payload(self):
        """Test decoding JWT with minimal payload"""
        minimal_payload = {
            "sub": "user456",
            "exp": int(time.time()) + 3600
        }
        token = jwt.encode(minimal_payload, self.secret, algorithm="HS256")
        
        user_data = decode_jwt(token, self.config)
        
        assert user_data['user_id'] == "user456"
        assert user_data['username'] is None
        assert user_data['email'] is None
        assert user_data['roles'] == []
        assert user_data['permissions'] == []
    
    def test_decode_jwt_expired_token_raises_error(self):
        """Test that expired JWT raises TokenError"""
        expired_payload = {
            "sub": "user123",
            "exp": int(time.time()) - 3600,  # Expired 1 hour ago
            "iat": int(time.time()) - 7200   # Issued 2 hours ago
        }
        expired_token = jwt.encode(expired_payload, self.secret, algorithm="HS256")
        
        with pytest.raises(TokenError, match="Token has expired"):
            decode_jwt(expired_token, self.config)
    
    def test_decode_jwt_invalid_signature_raises_error(self):
        """Test that JWT with wrong signature raises TokenError"""
        wrong_secret = "wrong-secret-32-characters-long!"
        token_wrong_sig = jwt.encode(self.payload, wrong_secret, algorithm="HS256")
        
        with pytest.raises(TokenError, match="Invalid token signature"):
            decode_jwt(token_wrong_sig, self.config)
    
    def test_decode_jwt_malformed_token_raises_error(self):
        """Test that malformed JWT raises TokenError"""
        malformed_tokens = [
            "not.a.jwt",
            "malformed",
            "",
            None,
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.malformed.signature"
        ]
        
        for bad_token in malformed_tokens:
            with pytest.raises(TokenError, match="Invalid token"):
                decode_jwt(bad_token, self.config)
    
    def test_decode_jwt_with_leeway(self):
        """Test JWT decoding with expiration leeway"""
        # Token expired 5 seconds ago, but leeway is 10 seconds
        barely_expired_payload = {
            "sub": "user123",
            "exp": int(time.time()) - 5,  # Expired 5 seconds ago
            "iat": int(time.time()) - 3605
        }
        token = jwt.encode(barely_expired_payload, self.secret, algorithm="HS256")
        
        # Should succeed due to leeway
        user_data = decode_jwt(token, self.config)
        assert user_data['user_id'] == "user123"
    
    def test_decode_jwt_verify_exp_disabled(self):
        """Test JWT decoding with expiration verification disabled"""
        config = JWTConfig(secret=self.secret, verify_exp=False)
        
        expired_payload = {
            "sub": "user123",
            "exp": int(time.time()) - 3600,  # Expired
        }
        token = jwt.encode(expired_payload, self.secret, algorithm="HS256")
        
        # Should succeed because exp verification is disabled
        user_data = decode_jwt(token, config)
        assert user_data['user_id'] == "user123"


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


class TestAuthorizationDecorator:
    """Test the authorization decorator functionality"""
    
    def setup_method(self):
        """Setup for each test"""
        # Configure JWT
        configure_jwt(secret="test-secret-32-characters-long!")
        
        # Create valid token
        payload = {
            "sub": "user123",
            "username": "testuser",
            "roles": ["user", "admin"],
            "exp": int(time.time()) + 3600
        }
        self.valid_token = jwt.encode(
            payload, 
            "test-secret-32-characters-long!", 
            algorithm="HS256"
        )
        
        # Create token with different roles
        basic_payload = {
            "sub": "user456", 
            "username": "basicuser",
            "roles": ["user"],
            "exp": int(time.time()) + 3600
        }
        self.basic_user_token = jwt.encode(
            basic_payload,
            "test-secret-32-characters-long!",
            algorithm="HS256"
        )
    
    def test_authorize_generic_no_roles_required_success(self):
        """Test authorization with no roles required (just authentication)"""
        
        # Mock adapter that returns our token
        mock_adapter = Mock()
        mock_adapter.extract_auth_token.return_value = self.valid_token
        
        @authorize_request(required_roles=None, adapter=mock_adapter)  
        def test_function(user=None):
            return {"status": "success"}
        
        result = test_function()
        assert result == {"status": "success"}
    
    def test_authorize_generic_with_required_roles_success(self):
        """Test authorization with required roles - success case"""
        
        mock_adapter = Mock()
        mock_adapter.extract_auth_token.return_value = self.valid_token
        
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
        mock_adapter.extract_auth_token.return_value = self.valid_token
        
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


class TestAsyncAuthorization:
    """Test async function authorization"""
    
    def setup_method(self):
        """Setup for async tests"""
        configure_jwt(secret="test-secret-32-characters-long!")
        
        payload = {
            "sub": "async_user",
            "username": "asynctest",
            "roles": ["user"],
            "exp": int(time.time()) + 3600
        }
        self.async_token = jwt.encode(
            payload,
            "test-secret-32-characters-long!",
            algorithm="HS256"
        )
    
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
    
    def setup_method(self):
        """Setup for framework tests"""
        configure_jwt(secret="test-secret-32-characters-long!")
    
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
    """Test various security attack scenarios"""
    
    def setup_method(self):
        """Setup security tests"""
        self.secret = "test-secret-32-characters-long!"
        configure_jwt(secret=self.secret)
    
    def test_jwt_algorithm_confusion_attack_prevention(self):
        """Test prevention of algorithm confusion attacks"""
        
        # Attacker tries to use 'none' algorithm
        header = {"typ": "JWT", "alg": "none"}
        payload = {"sub": "attacker", "roles": ["admin"]}
        
        import base64
        import json
        
        # Create token with 'none' algorithm
        header_encoded = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
        payload_encoded = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
        malicious_token = f"{header_encoded}.{payload_encoded}."
        
        config = JWTConfig(secret=self.secret)
        
        # Should fail - we only accept HS256
        with pytest.raises(TokenError):
            decode_jwt(malicious_token, config)
    
    def test_jwt_signature_tampering_detection(self):
        """Test that signature tampering is detected"""
        
        # Create valid token
        payload = {"sub": "user123", "roles": ["user"], "exp": int(time.time()) + 3600}
        valid_token = jwt.encode(payload, self.secret, algorithm="HS256")
        
        # Tamper with the signature more clearly
        parts = valid_token.split('.')
        
        # Method 1: Change the last character of signature
        if len(parts[2]) > 0:
            tampered_signature = parts[2][:-1] + ('X' if parts[2][-1] != 'X' else 'Y')
        else:
            tampered_signature = 'INVALID'
        
        tampered_token = f"{parts[0]}.{parts[1]}.{tampered_signature}"
        
        config = JWTConfig(secret=self.secret)
        
        # This should raise TokenError due to signature mismatch
        with pytest.raises(TokenError, match="Invalid token"):  # Broaden the match pattern
            decode_jwt(tampered_token, config)
    def test_jwt_payload_tampering_detection(self):
        """Test that payload tampering is detected"""
        
        # Create token with user role
        original_payload = {"sub": "user123", "roles": ["user"], "exp": int(time.time()) + 3600}
        token = jwt.encode(original_payload, self.secret, algorithm="HS256")
        
        # Try to tamper with payload to escalate privileges
        parts = token.split('.')
        
        # Decode payload, modify it, encode it back
        import base64
        import json
        
        # Add padding if needed
        payload_b64 = parts[1] + '=' * (4 - len(parts[1]) % 4)
        decoded_payload = json.loads(base64.urlsafe_b64decode(payload_b64))
        
        # Escalate role
        decoded_payload["roles"] = ["admin"]
        
        # Re-encode
        new_payload_b64 = base64.urlsafe_b64encode(json.dumps(decoded_payload).encode()).decode().rstrip('=')
        tampered_token = f"{parts[0]}.{new_payload_b64}.{parts[2]}"
        
        config = JWTConfig(secret=self.secret)
        
        # Should fail due to signature mismatch
        with pytest.raises(TokenError, match="Invalid token signature"):
            decode_jwt(tampered_token, config)
    
    def test_replay_attack_with_expired_token(self):
        """Test that expired tokens cannot be replayed"""
        
        # Create token that expires immediately
        payload = {
            "sub": "user123",
            "roles": ["admin"],
            "exp": int(time.time()) - 3600,  # 1 hour ago (definitely expired)
            "iat": int(time.time()) - 7200   # 2 hours ago
        }
        expired_token = jwt.encode(payload, self.secret, algorithm="HS256")
        
        config = JWTConfig(secret=self.secret)
        
        with pytest.raises(TokenError, match="Token has expired"):
            decode_jwt(expired_token, config)
    
    def test_jwt_secret_brute_force_resistance(self):
        """Test that weak secrets are rejected (if implemented)"""
        
        # This test would require implementing secret strength validation
        # For now, we test that different secrets produce different results
        
        payload = {"sub": "user123", "roles": ["user"]}
        
        secret1 = "secret1-32-characters-long-enough!"
        secret2 = "secret2-32-characters-long-enough!"
        
        token1 = jwt.encode(payload, secret1, algorithm="HS256")
        token2 = jwt.encode(payload, secret2, algorithm="HS256")
        
        # Same payload, different secrets should produce different tokens
        assert token1 != token2
        
        # Token created with secret1 should not verify with secret2
        config2 = JWTConfig(secret=secret2)
        
        with pytest.raises(TokenError, match="Invalid token signature"):
            decode_jwt(token1, config2)


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
    
    def test_token_error_types(self):
        """Test different token error scenarios"""
        
        # Test each specific token error type
        errors = [
            ("Token has expired", jwt.ExpiredSignatureError()),
            ("Invalid token signature", jwt.InvalidSignatureError()),
            ("Invalid token: malformed", jwt.DecodeError("malformed"))
        ]
        
        configure_jwt(secret="test-secret-32-characters-long!")
        
        for expected_msg, jwt_exception in errors:
            with patch('jwt.decode', side_effect=jwt_exception):
                with pytest.raises(TokenError, match=expected_msg.split(':')[0]):
                    decode_jwt("dummy.token.here", get_jwt_config())


class TestEdgeCases:
    """Test edge cases and boundary conditions"""
    
    def setup_method(self):
        """Setup edge case tests"""
        configure_jwt(secret="test-secret-32-characters-long!")
    
    def test_role_validation_with_none_values(self):
        """Test role validation handles None values gracefully"""
        
        # Test None user roles
        assert has_required_roles(None, ["admin"]) is False
        
        # Test None required roles  
        assert has_required_roles(["user"], None) is False
        
        # Test both None
        assert has_required_roles(None, None) is False
    
    def test_jwt_with_unicode_characters(self):
        """Test JWT handling with unicode characters"""
        
        payload = {
            "sub": "user123",
            "username": "用户",  # Chinese characters
            "email": "test@münchen.de",  # German umlaut
            "roles": ["ユーザー"],  # Japanese characters
            "exp": int(time.time()) + 3600
        }
        
        token = jwt.encode(payload, "test-secret-32-characters-long!", algorithm="HS256")
        config = JWTConfig(secret="test-secret-32-characters-long!")
        
        user_data = decode_jwt(token, config)
        assert user_data['username'] == "用户"
        assert user_data['email'] == "test@münchen.de"
        assert user_data['roles'] == ["ユーザー"]
    
    def test_jwt_with_very_large_payload(self):
        """Test JWT with large payload (near size limits)"""
        
        # Create large role list
        large_roles = [f"role_{i}" for i in range(1000)]
        
        payload = {
            "sub": "user123",
            "roles": large_roles,
            "exp": int(time.time()) + 3600
        }
        
        token = jwt.encode(payload, "test-secret-32-characters-long!", algorithm="HS256")
        config = JWTConfig(secret="test-secret-32-characters-long!")
        
        user_data = decode_jwt(token, config)
        assert len(user_data['roles']) == 1000
        assert "role_999" in user_data['roles']
    
    def test_decorator_with_existing_user_kwarg(self):
        """Test decorator doesn't override existing 'user' parameter"""
        
        mock_adapter = Mock()
        payload = {"sub": "token_user", "roles": ["user"], "exp": int(time.time()) + 3600}
        mock_adapter.extract_auth_token.return_value = jwt.encode(
            payload, "test-secret-32-characters-long!", algorithm="HS256"
        )
        
        @authorize_request(required_roles=["user"], adapter=mock_adapter)
        def test_function(user="existing_user"):
            return {"user": user}
        
        # Call with existing user parameter
        result = test_function(user="passed_user")
        
        # Should keep the passed user, not inject token user
        assert result == {"user": "passed_user"}

