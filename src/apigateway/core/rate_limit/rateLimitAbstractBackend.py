import time
import asyncio
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, Tuple
from threading import Lock


class RateLimitBackend(ABC):
    """Abstract interface for rate limiting storage backends"""
    
    @abstractmethod
    async def is_allowed(self, key: str, limit: int, window: int) -> Tuple[bool, Dict[str, Any]]:
        """
        Check if request is allowed and update counter.
        
        Args:
            key: Rate limit key (e.g., "user:123", "ip:192.168.1.1")
            limit: Maximum requests allowed
            window: Time window in seconds
            
        Returns:
            (is_allowed, metadata) where metadata contains:
            - remaining: requests remaining
            - reset_time: when window resets
            - retry_after: seconds to wait if rate limited
        """
        pass
    
    @abstractmethod
    async def reset(self, key: str) -> None:
        """Reset rate limit counter for key"""
        pass
    
    @abstractmethod
    async def get_usage(self, key: str, window: int) -> Dict[str, Any]:
        """Get current usage stats for key"""
        pass

