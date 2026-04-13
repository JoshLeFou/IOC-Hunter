"""
Rate limiter asynchrone pour respecter les quotas des APIs (ex: VT = 4 req/min).
Utilise un token bucket algorithm.
"""

import asyncio
import time
from collections import deque


class AsyncRateLimiter:
    """
    Rate limiter basé sur une fenêtre glissante.

    Usage:
        limiter = AsyncRateLimiter(max_calls=4, period=60)
        async with limiter:
            await make_api_call()
    """

    def __init__(self, max_calls: int, period: float):
        self.max_calls = max_calls
        self.period = period
        self._timestamps: deque[float] = deque()
        self._lock = asyncio.Lock()

    async def acquire(self):
        """Attend si nécessaire pour respecter le rate limit."""
        async with self._lock:
            now = time.monotonic()

            # Nettoyage des timestamps expirés
            while self._timestamps and self._timestamps[0] <= now - self.period:
                self._timestamps.popleft()

            if len(self._timestamps) >= self.max_calls:
                # On doit attendre que le plus ancien timestamp expire
                sleep_until = self._timestamps[0] + self.period
                wait_time = sleep_until - now
                if wait_time > 0:
                    await asyncio.sleep(wait_time)
                self._timestamps.popleft()

            self._timestamps.append(time.monotonic())

    async def __aenter__(self):
        await self.acquire()
        return self

    async def __aexit__(self, *exc):
        pass
