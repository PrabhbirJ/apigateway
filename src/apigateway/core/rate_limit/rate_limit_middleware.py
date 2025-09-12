# middleware/rate_limit_middleware.py
import asyncio
from typing import Callable, Optional, Any
from apigateway.core.rate_limit.RateLimitEngine import get_rate_limit_engine, KeyGenerators
from apigateway.core.rate_limit.rateLimitAbstractBackend import RateLimitBackend
from apigateway.exceptions.RateLimitError import RateLimitError


class FlaskRateLimitMiddleware:
    """Flask WSGI middleware for global rate limiting"""
    
    def __init__(
        self,
        wsgi_app,
        requests: int = 1000,
        window: int = 60,
        scope: str = "global",
        key_func: Optional[Callable] = None,
        backend: Optional[RateLimitBackend] = None
    ):
        self.wsgi_app = wsgi_app
        self.requests = requests
        self.window = window
        self.scope = scope
        self.key_func = key_func or KeyGenerators.ip_based
        
        if backend:
            from apigateway.core.rate_limit.RateLimitEngine import configure_rate_limiting
            configure_rate_limiting(backend)
    
    def __call__(self, environ, start_response):
        """WSGI middleware implementation"""
        
        # Create minimal Flask request-like object for key generation
        class MinimalRequest:
            def __init__(self, environ):
                self.remote_addr = environ.get('REMOTE_ADDR', 'unknown')
                self.headers = self._parse_headers(environ)
                self.environ = environ
            
            def _parse_headers(self, environ):
                headers = {}
                for key, value in environ.items():
                    if key.startswith('HTTP_'):
                        # Convert HTTP_X_FORWARDED_FOR -> X-Forwarded-For
                        header_name = key[5:].replace('_', '-').title()
                        headers[header_name] = value
                return headers
        
        request = MinimalRequest(environ)
        
        try:
            engine = get_rate_limit_engine()
            key = self.key_func(request, None, self.scope)
            
            # Run async check in sync context
            try:
                result = asyncio.run(engine.check_rate_limit(key, self.requests, self.window))
            except RuntimeError:
                # Handle case where event loop might already be running
                import concurrent.futures
                import threading
                
                result_container = {}
                
                def run_check():
                    loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(loop)
                    try:
                        result_container['result'] = loop.run_until_complete(
                            engine.check_rate_limit(key, self.requests, self.window)
                        )
                    finally:
                        loop.close()
                
                thread = threading.Thread(target=run_check)
                thread.start()
                thread.join()
                result = result_container['result']
            
            # Continue to app if allowed
            return self.wsgi_app(environ, start_response)
            
        except RateLimitError as e:
            # Return 429 response
            response_body = f'{{"error": "{e.message}", "code": "{e.code}", "details": {e.details}}}'.encode('utf-8')
            
            headers = [
                ('Content-Type', 'application/json'),
                ('Content-Length', str(len(response_body)))
            ]
            
            # Add rate limit headers
            if e.details:
                if 'retry_after' in e.details and e.details['retry_after']:
                    headers.append(('Retry-After', str(e.details['retry_after'])))
                if 'limit' in e.details:
                    headers.append(('X-RateLimit-Limit', str(e.details['limit'])))
                if 'remaining' in e.details:
                    headers.append(('X-RateLimit-Remaining', str(e.details.get('remaining', 0))))
            
            start_response('429 Too Many Requests', headers)
            return [response_body]


class DjangoRateLimitMiddleware:
    """Django middleware for global rate limiting"""
    
    def __init__(self, get_response):
        self.get_response = get_response
        
        # Load settings
        from django.conf import settings
        self.requests = getattr(settings, 'RATE_LIMIT_REQUESTS', 1000)
        self.window = getattr(settings, 'RATE_LIMIT_WINDOW', 60)
        self.scope = getattr(settings, 'RATE_LIMIT_SCOPE', 'global')
        
        # Set up backend if provided
        backend = getattr(settings, 'RATE_LIMIT_BACKEND', None)
        if backend:
            from apigateway.core.rate_limit.RateLimitEngine import configure_rate_limiting
            configure_rate_limiting(backend)
        
        self.key_func = KeyGenerators.ip_based
    
    def __call__(self, request):
        """Django middleware implementation"""
        try:
            engine = get_rate_limit_engine()
            key = self.key_func(request, None, self.scope)
            
            # Run async check in sync context
            result = asyncio.run(engine.check_rate_limit(key, self.requests, self.window))
            
            # Continue to view
            response = self.get_response(request)
            
            # Add rate limit headers to response
            if hasattr(response, '__setitem__'):  # Check if headers can be set
                response['X-RateLimit-Limit'] = str(self.requests)
                response['X-RateLimit-Window'] = str(self.window)
                if 'remaining' in result:
                    response['X-RateLimit-Remaining'] = str(result['remaining'])
            
            return response
            
        except RateLimitError as e:
            from django.http import JsonResponse
            
            response = JsonResponse({
                "error": e.message,
                "code": e.code,
                "details": e.details
            }, status=429)
            
            # Add rate limit headers
            if e.details:
                if 'retry_after' in e.details and e.details['retry_after']:
                    response['Retry-After'] = str(e.details['retry_after'])
                if 'limit' in e.details:
                    response['X-RateLimit-Limit'] = str(e.details['limit'])
                if 'remaining' in e.details:
                    response['X-RateLimit-Remaining'] = str(e.details.get('remaining', 0))
            
            return response


class FastAPIRateLimitMiddleware:
    """FastAPI middleware for global rate limiting"""
    
    def __init__(
        self,
        app,
        requests: int = 1000,
        window: int = 60,
        scope: str = "global",
        key_func: Optional[Callable] = None,
        backend: Optional[RateLimitBackend] = None
    ):
        self.app = app
        self.requests = requests
        self.window = window
        self.scope = scope
        self.key_func = key_func or KeyGenerators.ip_based
        
        if backend:
            from apigateway.core.rate_limit.RateLimitEngine import configure_rate_limiting
            configure_rate_limiting(backend)
    
    async def __call__(self, scope, receive, send):
        """ASGI middleware implementation"""
        if scope["type"] != "http":
            # Not HTTP request, pass through
            await self.app(scope, receive, send)
            return
        
        # Create request-like object for key generation
        class ASGIRequest:
            def __init__(self, scope):
                self.scope = scope
                self.remote_addr = self._get_client_ip(scope)
                self.headers = dict(scope.get("headers", []))
            
            def _get_client_ip(self, scope):
                # Get client IP from ASGI scope
                client = scope.get("client")
                if client:
                    return client[0]  # (host, port) tuple
                return "unknown"
        
        request = ASGIRequest(scope)
        
        try:
            engine = get_rate_limit_engine()
            key = self.key_func(request, None, self.scope)
            
            # Check rate limit
            result = await engine.check_rate_limit(key, self.requests, self.window)
            
            # Create response modifier to add headers
            original_send = send
            
            async def send_with_headers(message):
                if message["type"] == "http.response.start":
                    headers = list(message.get("headers", []))
                    
                    # Add rate limit headers
                    headers.append([b"x-ratelimit-limit", str(self.requests).encode()])
                    headers.append([b"x-ratelimit-window", str(self.window).encode()])
                    if 'remaining' in result:
                        headers.append([b"x-ratelimit-remaining", str(result['remaining']).encode()])
                    
                    message["headers"] = headers
                
                await original_send(message)
            
            # Continue to app
            await self.app(scope, receive, send_with_headers)
            
        except RateLimitError as e:
            # Send 429 response
            response_body = {
                "error": e.message,
                "code": e.code, 
                "details": e.details
            }
            
            import json
            body = json.dumps(response_body).encode()
            
            headers = [
                [b"content-type", b"application/json"],
                [b"content-length", str(len(body)).encode()]
            ]
            
            # Add rate limit headers
            if e.details:
                if 'retry_after' in e.details and e.details['retry_after']:
                    headers.append([b"retry-after", str(e.details['retry_after']).encode()])
                if 'limit' in e.details:
                    headers.append([b"x-ratelimit-limit", str(e.details['limit']).encode()])
                if 'remaining' in e.details:
                    headers.append([b"x-ratelimit-remaining", str(e.details.get('remaining', 0)).encode()])
            
            await send({
                "type": "http.response.start",
                "status": 429,
                "headers": headers
            })
            
            await send({
                "type": "http.response.body",
                "body": body
            })


# Usage Examples:
"""
# Flask - Global rate limiting
from apigateway.middleware.rate_limit_middleware import FlaskRateLimitMiddleware
from apigateway.core.rate_limit.backends import RedisBackend

app = Flask(__name__)

# Setup Redis backend
import redis
redis_client = redis.Redis(host='localhost', port=6379)
backend = RedisBackend(redis_client)

# Add middleware
app.wsgi_app = FlaskRateLimitMiddleware(
    app.wsgi_app,
    requests=1000,    # 1000 requests
    window=60,        # per minute
    backend=backend
)

# Django - settings.py
MIDDLEWARE = [
    'apigateway.middleware.rate_limit_middleware.DjangoRateLimitMiddleware',
    # ... other middleware
]

# Django settings
RATE_LIMIT_REQUESTS = 1000
RATE_LIMIT_WINDOW = 60
RATE_LIMIT_BACKEND = RedisBackend(redis_client)

# FastAPI - Global middleware
from fastapi import FastAPI
from apigateway.middleware.rate_limit_middleware import FastAPIRateLimitMiddleware

app = FastAPI()

app.add_middleware(
    FastAPIRateLimitMiddleware,
    requests=1000,
    window=60,
    backend=backend
)

# Both middleware AND decorators work together:
app.wsgi_app = FlaskRateLimitMiddleware(app.wsgi_app, requests=1000, window=60)  # Global: 1000/min

@rate_limit_flask(requests=10, window=60)  # Per endpoint: 10/min
def specific_endpoint():
    pass

# The more restrictive limit applies!
"""