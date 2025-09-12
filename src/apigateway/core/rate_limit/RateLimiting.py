import inspect
from functools import wraps
from typing import Callable, Optional, List, Union
from apigateway.core.adapters.base_adapter import FrameworkAdapter
from apigateway.core.adapters.django import DjangoAdapter
from apigateway.core.adapters.fastapi import FastAPIAdapter
from apigateway.core.adapters.flask import FlaskAdapter
from apigateway.core.adapters.generic import GenericAdapter
from apigateway.core.rate_limit.RateLimitEngine import get_rate_limit_engine, KeyGenerators
from apigateway.exceptions.RateLimitError import RateLimitError


def rate_limit_request(
    requests: int,
    window: int,
    scope: str = "default",
    key_func: Optional[Callable] = None,
    adapter: Optional[FrameworkAdapter] = None,
):
    """
    Framework-agnostic rate limiting decorator
    
    Args:
        requests: Maximum requests allowed
        window: Time window in seconds  
        scope: Rate limit scope (for grouping)
        key_func: Custom key generation function
        adapter: Framework adapter (if None, uses GenericAdapter)
    
    Pipeline:
        extract_key_info → generate_key → check_rate_limit → function
    """
    
    # Use GenericAdapter if no adapter specified
    if adapter is None:
        adapter = GenericAdapter()
    
    # Default key generator if none provided
    if key_func is None:
        key_func = KeyGenerators.ip_based
    
    def decorator(func: Callable):
        is_async = inspect.iscoroutinefunction(func)
        
        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            try:
                engine = get_rate_limit_engine()
                
                # Step 1: Extract key info from request
                key_info = adapter.extract_rate_limit_key_info(*args, **kwargs)
                
                # Step 2: Generate rate limit key
                user_context = kwargs.get('user')  # From auth decorator if present
                key = key_func(key_info['request'], user_context, scope)
                
                # Step 3: Check rate limit
                result = await engine.check_rate_limit(key, requests, window)
                
                # Step 4: Add rate limit info to response (optional)
                kwargs['_rate_limit_info'] = result
                
                return await func(*args, **kwargs)
                
            except RateLimitError as e:
                return adapter.handle_rate_limit_error(e)
        
        @wraps(func)
        def sync_wrapper(*args, **kwargs):
            try:
                import asyncio
                engine = get_rate_limit_engine()
                
                # Extract key info
                key_info = adapter.extract_rate_limit_key_info(*args, **kwargs)
                
                # Generate key
                user_context = kwargs.get('user')
                key = key_func(key_info['request'], user_context, scope)
                
                # Check rate limit (handle async in sync context)
                try:
                    # Try to use existing event loop
                    loop = asyncio.get_event_loop()
                    if loop.is_running():
                        # Already in async context - this shouldn't happen in sync wrapper
                        # but handle it gracefully
                        import concurrent.futures
                        import threading
                        
                        result_container = {}
                        exception_container = {}
                        
                        def run_check():
                            try:
                                new_loop = asyncio.new_event_loop()
                                asyncio.set_event_loop(new_loop)
                                result_container['result'] = new_loop.run_until_complete(
                                    engine.check_rate_limit(key, requests, window)
                                )
                            except Exception as e:
                                exception_container['error'] = e
                            finally:
                                new_loop.close()
                        
                        thread = threading.Thread(target=run_check)
                        thread.start()
                        thread.join()
                        
                        if 'error' in exception_container:
                            raise exception_container['error']
                        result = result_container['result']
                    else:
                        # Normal case - run in current event loop
                        result = loop.run_until_complete(
                            engine.check_rate_limit(key, requests, window)
                        )
                except RuntimeError:
                    # No event loop - create new one
                    result = asyncio.run(engine.check_rate_limit(key, requests, window))
                
                # Add rate limit info
                kwargs['_rate_limit_info'] = result
                
                return func(*args, **kwargs)
                
            except RateLimitError as e:
                return adapter.handle_rate_limit_error(e)
                
        return async_wrapper if is_async else sync_wrapper
    return decorator


# Convenience functions for different frameworks (same pattern as auth/validation)
def rate_limit_flask(
    requests: int,
    window: int,
    scope: str = "default",
    key_func: Optional[Callable] = None,
    **kwargs
):
    """Convenience function for Flask rate limiting"""
    return rate_limit_request(
        requests=requests,
        window=window,
        scope=scope,
        key_func=key_func,
        adapter=FlaskAdapter(),
        **kwargs
    )


def rate_limit_django(
    requests: int,
    window: int,
    scope: str = "default", 
    key_func: Optional[Callable] = None,
    **kwargs
):
    """Convenience function for Django rate limiting"""
    return rate_limit_request(
        requests=requests,
        window=window,
        scope=scope,
        key_func=key_func,
        adapter=DjangoAdapter(),
        **kwargs
    )


def rate_limit_fastapi(
    requests: int,
    window: int,
    scope: str = "default",
    key_func: Optional[Callable] = None,
    **kwargs
):
    """Convenience function for FastAPI rate limiting"""
    return rate_limit_request(
        requests=requests,
        window=window,
        scope=scope,
        key_func=key_func,
        adapter=FastAPIAdapter(),
        **kwargs
    )


def rate_limit_generic(
    requests: int,
    window: int,
    scope: str = "default",
    key_func: Optional[Callable] = None,
    **kwargs
):
    """Convenience function for generic/custom frameworks"""
    return rate_limit_request(
        requests=requests,
        window=window,
        scope=scope,
        key_func=key_func,
        adapter=GenericAdapter(),
        **kwargs
    )


# Advanced key generators
class AdvancedKeyGenerators:
    """Advanced key generation strategies"""
    
    @staticmethod
    def user_and_endpoint(request, user=None, scope="default") -> str:
        """Rate limit by user + endpoint combination"""
        user_part = f"user:{user['user_id']}" if user and user.get('user_id') else f"ip:{getattr(request, 'remote_addr', 'unknown')}"
        endpoint = getattr(request, 'endpoint', getattr(request, 'path', 'unknown'))
        return f"rate_limit:{scope}:{user_part}:endpoint:{endpoint}"
    
    @staticmethod
    def tiered_by_role(request, user=None, scope="default") -> str:
        """Different rate limits based on user role"""
        if user and user.get('roles'):
            if 'premium' in user['roles']:
                tier = 'premium'
            elif 'admin' in user['roles']:
                tier = 'admin'
            else:
                tier = 'basic'
        else:
            tier = 'anonymous'
        
        user_id = user.get('user_id') if user else getattr(request, 'remote_addr', 'unknown')
        return f"rate_limit:{scope}:tier:{tier}:user:{user_id}"
    
    @staticmethod
    def geographic(request, user=None, scope="default") -> str:
        """Rate limit by geographic region (requires IP geolocation)"""
        # This would need integration with IP geolocation service
        # For now, fallback to IP-based
        ip = getattr(request, 'remote_addr', 'unknown')
        # In real implementation: region = get_country_from_ip(ip)
        region = 'unknown'  # Placeholder
        return f"rate_limit:{scope}:region:{region}:ip:{ip}"


# Usage Examples:
"""
# Basic rate limiting:
@rate_limit_flask(requests=100, window=60)  # 100 requests per minute
def api_endpoint():
    pass

# User-based rate limiting:
@rate_limit_flask(requests=50, window=60, key_func=KeyGenerators.user_based)
def user_endpoint():
    pass

# Custom key function:
def custom_key(request, user=None, scope="default"):
    api_key = request.headers.get('X-API-Key', 'anonymous')
    return f"rate_limit:{scope}:api:{api_key}"

@rate_limit_flask(requests=1000, window=3600, key_func=custom_key)  # 1000/hour per API key
def api_key_endpoint():
    pass

# Combined with auth and validation (THE POWER COMBO!):
@validate_flask(UserCreateSchema)
@authorize_flask(['admin'])
@rate_limit_flask(requests=10, window=60, key_func=KeyGenerators.user_based)  # 10/min per admin user
def create_user(validated, user):
    return {
        'message': f'Admin {user["username"]} created {validated.username}',
        'rate_limit': kwargs.get('_rate_limit_info', {})  # Optional: include rate limit info
    }

# Advanced key generation:
@rate_limit_flask(requests=100, window=60, key_func=AdvancedKeyGenerators.tiered_by_role)
def tiered_endpoint():
    # Premium users get higher limits automatically
    pass

# Multiple rate limits on same endpoint:
@rate_limit_flask(requests=1000, window=3600, scope='hourly')  # 1000/hour
@rate_limit_flask(requests=100, window=60, scope='minute')    # 100/minute  
def heavily_limited_endpoint():
    # Both rate limits must pass
    pass
"""