from apigateway.core.rate_limit.rateLimitAbstractBackend import RateLimitBackend
from typing import Tuple,Dict,Any
import time

class RedisBackend(RateLimitBackend):
    """Redis-based rate limiting backend (production)"""
    
    def __init__(self, redis_client):
        """
        Initialize with user-provided Redis client.
        
        Args:
            redis_client: User's Redis client (redis.Redis or redis.asyncio.Redis)
        """
        self.redis = redis_client
        self._is_async = (
        hasattr(redis_client, 'aioredis') or 
        'asyncio' in str(type(redis_client)) or
        hasattr(redis_client, '_async')  # Common async Redis marker
    )
    
    async def is_allowed(self, key: str, limit: int, window: int) -> Tuple[bool, Dict[str, Any]]:
        """Redis-based token bucket using Lua script for atomicity"""
        
        # Lua script for atomic token bucket operations
        lua_script = """
        local key = KEYS[1]
        local limit = tonumber(ARGV[1])
        local window = tonumber(ARGV[2])
        local now = tonumber(ARGV[3])
        
        -- Get current bucket state
        local bucket = redis.call('HMGET', key, 'tokens', 'last_refill', 'window_start')
        local tokens = tonumber(bucket[1])
        local last_refill = tonumber(bucket[2])
        local window_start = tonumber(bucket[3])
        
        -- Initialize if doesn't exist
        if not tokens then
            tokens = limit - 1
            last_refill = now
            window_start = now
            
            redis.call('HMSET', key, 'tokens', tokens, 'last_refill', last_refill, 'window_start', window_start)
            redis.call('EXPIRE', key, window * 2)  -- TTL for cleanup
            
            return {1, tokens, window_start + window, 0}  -- allowed, remaining, reset_time, retry_after
        end
        
        -- Calculate tokens to add
        local time_passed = now - last_refill
        local tokens_to_add = (time_passed / window) * limit
        tokens = math.min(limit, tokens + tokens_to_add)
        
        -- Update last refill time
        redis.call('HSET', key, 'last_refill', now)
        
        if tokens >= 1.0 then
            -- Request allowed
            tokens = tokens - 1.0
            redis.call('HSET', key, 'tokens', tokens)
            return {1, math.floor(tokens), window_start + window, 0}
        else
            -- Rate limited
            local retry_after = math.ceil((1.0 - tokens) * window / limit)
            return {0, 0, window_start + window, retry_after}
        end
        """
        
        now = time.time()
        
        if self._is_async:
            result = await self.redis.eval(lua_script, 1, key, limit, window, now)
        else:
            result = self.redis.eval(lua_script, 1, key, limit, window, now)
        
        allowed, remaining, reset_time, retry_after = result
        
        return bool(allowed), {
            'remaining': int(remaining),
            'reset_time': int(reset_time),
            'retry_after': int(retry_after)
        }
    
    async def reset(self, key: str) -> None:
        """Reset rate limit counter for key"""
        if self._is_async:
            await self.redis.delete(key)
        else:
            self.redis.delete(key)
    
    async def get_usage(self, key: str, window: int) -> Dict[str, Any]:
        """Get current usage stats from Redis"""
        if self._is_async:
            bucket = await self.redis.hmget(key, 'tokens', 'window_start')
        else:
            bucket = self.redis.hmget(key, 'tokens', 'window_start')
        
        tokens, window_start = bucket
        
        if tokens is None:
            return {'usage': 0, 'remaining': window, 'window_start': None}
        
        tokens = float(tokens)
        return {
            'usage': int(window - tokens),
            'remaining': int(tokens),
            'window_start': float(window_start) if window_start else None
        }