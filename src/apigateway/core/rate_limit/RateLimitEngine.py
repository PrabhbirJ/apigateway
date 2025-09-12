# core/rate_limit/engine.py
from typing import Callable, Dict, Any, Optional, Awaitable, Union

from apigateway.core.rate_limit.MemoryBackend import MemoryBackend
from apigateway.core.rate_limit.rateLimitAbstractBackend import RateLimitBackend
from apigateway.exceptions.RateLimitError import RateLimitExceeded


class RateLimitEngine:
    """Core rate limiting engine"""
    
    def __init__(self, backend: RateLimitBackend):
        self.backend = backend
    
    async def check_rate_limit(
        self, 
        key: str, 
        limit: int, 
        window: int,
        raise_on_limit: bool = True
    ) -> Dict[str, Any]:
        """
        Check rate limit for given key.
        
        Args:
            key: Rate limit identifier
            limit: Maximum requests allowed
            window: Time window in seconds
            raise_on_limit: Whether to raise exception when rate limited
            
        Returns:
            Metadata dict with remaining requests, reset time, etc.
            
        Raises:
            RateLimitExceeded: If rate limited and raise_on_limit=True
        """
        allowed, metadata = await self.backend.is_allowed(key, limit, window)
        
        if not allowed and raise_on_limit:
            raise RateLimitExceeded(
                limit=limit,
                window=window,
                retry_after=metadata.get('retry_after'),
                current_usage=limit - metadata.get('remaining', 0)
            )
        
        return {
            'allowed': allowed,
            'limit': limit,
            'window': window,
            **metadata
        }
    
    async def reset_key(self, key: str) -> None:
        """Reset rate limit for specific key"""
        await self.backend.reset(key)
    
    async def get_usage(self, key: str, window: int) -> Dict[str, Any]:
        """Get current usage stats for key"""
        return await self.backend.get_usage(key, window)


# Global rate limit engine
_rate_limit_engine: Optional[RateLimitEngine] = None


def configure_rate_limiting(backend: Optional[RateLimitBackend] = None):
    """Configure global rate limiting backend"""
    global _rate_limit_engine
    
    if backend is None:
        # Default to memory backend for development
        backend = MemoryBackend()
    
    _rate_limit_engine = RateLimitEngine(backend)


def get_rate_limit_engine() -> RateLimitEngine:
    """Get current rate limit engine (auto-initializes with memory backend)"""
    global _rate_limit_engine
    
    if _rate_limit_engine is None:
        # Auto-configure with memory backend
        configure_rate_limiting()
    
    return _rate_limit_engine


# Key generation functions
def generate_ip_key(ip: str, scope: str = "default") -> str:
    """Generate rate limit key based on IP address"""
    return f"rate_limit:{scope}:ip:{ip}"


def generate_user_key(user_id: str, scope: str = "default") -> str:
    """Generate rate limit key based on user ID"""
    return f"rate_limit:{scope}:user:{user_id}"


def generate_api_key(api_key: str, scope: str = "default") -> str:
    """Generate rate limit key based on API key"""
    return f"rate_limit:{scope}:api:{api_key}"


def generate_custom_key(identifier: str, scope: str = "default") -> str:
    """Generate custom rate limit key"""
    return f"rate_limit:{scope}:custom:{identifier}"


# Default key generators
class KeyGenerators:
    """Common key generation functions"""
    
    @staticmethod
    def ip_based(request, user=None, scope="default") -> str:
        """Rate limit by IP address"""
        ip = getattr(request, 'remote_addr', 'unknown')
        return generate_ip_key(ip, scope)
    
    @staticmethod  
    def user_based(request, user=None, scope="default") -> str:
        """Rate limit by user (falls back to IP if no user)"""
        if user and user.get('user_id'):
            return generate_user_key(str(user['user_id']), scope)
        
        # Fallback to IP-based if no user
        ip = getattr(request, 'remote_addr', 'unknown') 
        return generate_ip_key(ip, scope)
    
    @staticmethod
    def api_key_based(request, user=None, scope="default") -> str:
        """Rate limit by API key from headers"""
        api_key = None
        
        # Try different header names
        if hasattr(request, 'headers'):
            api_key = (
                request.headers.get('X-API-Key') or
                request.headers.get('Authorization') or
                request.headers.get('API-Key')
            )
        
        if api_key:
            return generate_api_key(api_key, scope)
        
        # Fallback to IP-based
        ip = getattr(request, 'remote_addr', 'unknown')
        return generate_ip_key(ip, scope)