"""Small circuit breaker to avoid hammering an unavailable upstream service."""
import threading
import time
from .common import APIError

class CircuitBreaker:
    def __init__(self,threshold=3,cooldown=10,clock=time.monotonic):
        self.threshold,self.cooldown,self.clock=threshold,cooldown,clock
        self.failures=0
        self.open_until=0
        self.lock=threading.RLock()

    def call(self,func):
        with self.lock:
            if self.clock()<self.open_until:
                raise APIError(503,'Circuit open: upstream recently failed')
        try:
            result=func()
        except (APIError,TimeoutError,OSError):
            with self.lock:
                self.failures+=1
                if self.failures>=self.threshold:self.open_until=self.clock()+self.cooldown
            raise
        else:
            with self.lock:
                self.failures=0
                self.open_until=0
            return result
