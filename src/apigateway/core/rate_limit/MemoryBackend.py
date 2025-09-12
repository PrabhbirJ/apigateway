import time
import asyncio
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, Tuple
from threading import Lock
from apigateway.core.rate_limit.rateLimitAbstractBackend import RateLimitBackend

class MemoryBackend(RateLimitBackend):
    """In-memory rate limiting backend (development only)"""
    
    def __init__(self):
        self._data: Dict[str, Dict[str, Any]] = {}
        self._lock = Lock()
    
    async def is_allowed(self, key: str, limit: int, window: int) -> Tuple[bool, Dict[str, Any]]:
        """Token bucket algorithm implementation"""
        now = time.time()
        
        with self._lock:
            if key not in self._data:
                # First request - initialize bucket
                self._data[key] = {
                    'tokens': limit - 1,  # Use one token
                    'last_refill': now,
                    'window_start': now
                }
                
                return True, {
                    'remaining': limit - 1,
                    'reset_time': int(now + window),
                    'retry_after': 0
                }
            
            bucket = self._data[key]
            
            # Calculate tokens to add (refill rate: limit tokens per window)
            time_passed = now - bucket['last_refill']
            tokens_to_add = (time_passed / window) * limit
            
            # Update bucket
            bucket['tokens'] = min(limit, bucket['tokens'] + tokens_to_add)
            bucket['last_refill'] = now
            
            if bucket['tokens'] >= 1.0:
                # Request allowed
                bucket['tokens'] -= 1.0
                remaining = int(bucket['tokens'])
                
                return True, {
                    'remaining': remaining,
                    'reset_time': int(bucket['window_start'] + window),
                    'retry_after': 0
                }
            else:
                # Rate limited
                retry_after = int((1.0 - bucket['tokens']) * window / limit)
                
                return False, {
                    'remaining': 0,
                    'reset_time': int(bucket['window_start'] + window),
                    'retry_after': retry_after
                }
    
    async def reset(self, key: str) -> None:
        """Reset rate limit counter for key"""
        with self._lock:
            if key in self._data:
                del self._data[key]
    
    async def get_usage(self, key: str, window: int) -> Dict[str, Any]:
        """Get current usage stats"""
        with self._lock:
            if key not in self._data:
                return {'usage': 0, 'remaining': window}
            
            bucket = self._data[key]
            return {
                'usage': int(window - bucket['tokens']),
                'remaining': int(bucket['tokens']),
                'window_start': bucket['window_start']
            }

