"""
Performance monitoring and optimization.
"""

import asyncio
import time
import psutil
import gc
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass
from contextlib import contextmanager
import logging
import functools

from src.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class PerformanceMetrics:
    """Performance metrics container."""
    execution_time: float
    memory_used_mb: float
    cpu_percent: float
    calls: int = 1
    errors: int = 0
    
    def __add__(self, other):
        """Combine metrics."""
        return PerformanceMetrics(
            execution_time=self.execution_time + other.execution_time,
            memory_used_mb=max(self.memory_used_mb, other.memory_used_mb),
            cpu_percent=max(self.cpu_percent, other.cpu_percent),
            calls=self.calls + other.calls,
            errors=self.errors + other.errors,
        )
    
    def average(self):
        """Return average metrics."""
        if self.calls == 0:
            return self
        return PerformanceMetrics(
            execution_time=self.execution_time / self.calls,
            memory_used_mb=self.memory_used_mb,
            cpu_percent=self.cpu_percent,
            calls=self.calls,
            errors=self.errors,
        )


class PerformanceMonitor:
    """Monitors performance of functions and operations."""
    
    def __init__(self):
        """Initialize monitor."""
        self.metrics: Dict[str, PerformanceMetrics] = {}
        self.process = psutil.Process()
    
    @contextmanager
    def measure(self, name: str):
        """Measure performance of a code block.
        
        Args:
            name: Name of the operation
        """
        start_time = time.perf_counter()
        start_memory = self.process.memory_info().rss
        
        try:
            yield
            error = False
        except Exception:
            error = True
            raise
        finally:
            end_time = time.perf_counter()
            end_memory = self.process.memory_info().rss
            
            execution_time = end_time - start_time
            memory_used = (end_memory - start_memory) / 1024 / 1024  # MB
            cpu_percent = self.process.cpu_percent()
            
            metrics = PerformanceMetrics(
                execution_time=execution_time,
                memory_used_mb=memory_used,
                cpu_percent=cpu_percent,
                errors=1 if error else 0,
            )
            
            if name in self.metrics:
                self.metrics[name] += metrics
            else:
                self.metrics[name] = metrics
    
    def profile_function(self, func: Callable):
        """Decorator to profile a function.
        
        Args:
            func: Function to profile
            
        Returns:
            Wrapped function
        """
        @functools.wraps(func)
        async def async_wrapper(*args, **kwargs):
            with self.measure(func.__name__):
                return await func(*args, **kwargs)
        
        @functools.wraps(func)
        def sync_wrapper(*args, **kwargs):
            with self.measure(func.__name__):
                return func(*args, **kwargs)
        
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        return sync_wrapper
    
    def get_metrics(self, name: Optional[str] = None) -> Dict[str, Any]:
        """Get performance metrics.
        
        Args:
            name: Specific metric name or None for all
            
        Returns:
            Metrics dictionary
        """
        if name:
            if name in self.metrics:
                metrics = self.metrics[name]
                return {
                    'name': name,
                    'total_time': metrics.execution_time,
                    'avg_time': metrics.execution_time / metrics.calls,
                    'max_memory_mb': metrics.memory_used_mb,
                    'max_cpu_percent': metrics.cpu_percent,
                    'calls': metrics.calls,
                    'errors': metrics.errors,
                }
            return {}
        
        return {
            name: {
                'total_time': metrics.execution_time,
                'avg_time': metrics.execution_time / metrics.calls,
                'max_memory_mb': metrics.memory_used_mb,
                'max_cpu_percent': metrics.cpu_percent,
                'calls': metrics.calls,
                'errors': metrics.errors,
            }
            for name, metrics in self.metrics.items()
        }
    
    def get_slowest_operations(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get slowest operations.
        
        Args:
            limit: Maximum number of operations
            
        Returns:
            List of slow operations
        """
        sorted_ops = sorted(
            self.metrics.items(),
            key=lambda x: x[1].execution_time / x[1].calls,
            reverse=True
        )[:limit]
        
        return [
            {
                'name': name,
                'avg_time': metrics.execution_time / metrics.calls,
                'total_time': metrics.execution_time,
                'calls': metrics.calls,
            }
            for name, metrics in sorted_ops
        ]
    
    def clear_metrics(self):
        """Clear all metrics."""
        self.metrics.clear()


class MemoryOptimizer:
    """Optimizes memory usage."""
    
    def __init__(self):
        """Initialize optimizer."""
        self.process = psutil.Process()
    
    def get_memory_info(self) -> Dict[str, Any]:
        """Get current memory information.
        
        Returns:
            Memory info dictionary
        """
        memory = self.process.memory_info()
        memory_percent = self.process.memory_percent()
        
        return {
            'rss_mb': memory.rss / 1024 / 1024,
            'vms_mb': memory.vms / 1024 / 1024,
            'percent': memory_percent,
            'available_mb': psutil.virtual_memory().available / 1024 / 1024,
            'total_mb': psutil.virtual_memory().total / 1024 / 1024,
        }
    
    def optimize_memory(self):
        """Run memory optimization routines."""
        # Force garbage collection
        collected = gc.collect()
        
        # Clear Python caches
        import sys
        if hasattr(sys, 'getobjects'):
            # Only in debug builds
            pass
        
        memory_info = self.get_memory_info()
        logger.info(f"Memory optimization: freed {collected} objects")
        logger.info(f"Memory usage: {memory_info['rss_mb']:.1f}MB ({memory_info['percent']:.1f}%)")
        
        return collected
    
    def check_memory_limit(self, limit_mb: float = 1024) -> bool:
        """Check if memory usage exceeds limit.
        
        Args:
            limit_mb: Memory limit in MB
            
        Returns:
            True if over limit
        """
        memory_info = self.get_memory_info()
        return memory_info['rss_mb'] > limit_mb
    
    @contextmanager
    def memory_limit(self, limit_mb: float = 1024):
        """Context manager to enforce memory limit.
        
        Args:
            limit_mb: Memory limit in MB
        """
        start_memory = self.process.memory_info().rss
        
        try:
            yield
        finally:
            current_memory = self.process.memory_info().rss
            memory_used = (current_memory - start_memory) / 1024 / 1024
            
            if memory_used > limit_mb:
                logger.warning(
                    f"Memory usage exceeded limit: {memory_used:.1f}MB > {limit_mb}MB"
                )
                
                # Try to optimize memory
                self.optimize_memory()


class CacheManager:
    """Manages caching for performance."""
    
    def __init__(self, max_size_mb: float = 100):
        """Initialize cache manager.
        
        Args:
            max_size_mb: Maximum cache size in MB
        """
        self.max_size_mb = max_size_mb
        self.cache: Dict[str, Any] = {}
        self.access_times: Dict[str, float] = {}
        self.sizes: Dict[str, int] = {}
        
        self.total_size_bytes = 0
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get value from cache.
        
        Args:
            key: Cache key
            default: Default value if not found
            
        Returns:
            Cached value or default
        """
        if key in self.cache:
            self.access_times[key] = time.time()
            return self.cache[key]
        return default
    
    def set(self, key: str, value: Any, size_bytes: Optional[int] = None):
        """Set value in cache.
        
        Args:
            key: Cache key
            value: Value to cache
            size_bytes: Estimated size in bytes (calculated if None)
        """
        # Calculate size if not provided
        if size_bytes is None:
            size_bytes = self._estimate_size(value)
        
        # Remove old entries if cache is full
        while (self.total_size_bytes + size_bytes) > (self.max_size_mb * 1024 * 1024):
            self._evict_oldest()
        
        # Update cache
        if key in self.cache:
            old_size = self.sizes[key]
            self.total_size_bytes -= old_size
        
        self.cache[key] = value
        self.access_times[key] = time.time()
        self.sizes[key] = size_bytes
        self.total_size_bytes += size_bytes
    
    def _estimate_size(self, value: Any) -> int:
        """Estimate size of value in bytes.
        
        Args:
            value: Value to estimate
            
        Returns:
            Estimated size in bytes
        """
        import sys
        
        if isinstance(value, (str, bytes, bytearray)):
            return len(value)
        elif isinstance(value, (int, float, bool)):
            return 28  # Approximate size for Python objects
        else:
            # Rough estimate
            return sys.getsizeof(value, 0)
    
    def _evict_oldest(self):
        """Evict oldest cache entry."""
        if not self.cache:
            return
        
        # Find oldest accessed key
        oldest_key = min(self.access_times.items(), key=lambda x: x[1])[0]
        
        # Remove from cache
        size = self.sizes.pop(oldest_key)
        self.cache.pop(oldest_key)
        self.access_times.pop(oldest_key)
        
        self.total_size_bytes -= size
    
    def clear(self):
        """Clear entire cache."""
        self.cache.clear()
        self.access_times.clear()
        self.sizes.clear()
        self.total_size_bytes = 0
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics.
        
        Returns:
            Cache statistics
        """
        return {
            'entries': len(self.cache),
            'size_mb': self.total_size_bytes / 1024 / 1024,
            'max_size_mb': self.max_size_mb,
            'hit_rate': self._calculate_hit_rate(),
        }
    
    def _calculate_hit_rate(self) -> float:
        """Calculate cache hit rate.
        
        Returns:
            Hit rate (0.0 to 1.0)
        """
        # This would require tracking hits and misses
        # For simplicity, return 0 for now
        return 0.0


class AsyncBatchProcessor:
    """Processes items in batches asynchronously."""
    
    def __init__(self, max_concurrent: int = 10, batch_size: int = 100):
        """Initialize batch processor.
        
        Args:
            max_concurrent: Maximum concurrent operations
            batch_size: Items per batch
        """
        self.max_concurrent = max_concurrent
        self.batch_size = batch_size
        self.semaphore = asyncio.Semaphore(max_concurrent)
    
    async def process_batch(self, items: List[Any], process_func: Callable) -> List[Any]:
        """Process items in batches.
        
        Args:
            items: Items to process
            process_func: Async function to process each item
            
        Returns:
            List of results
        """
        results = []
        
        # Process in batches
        for i in range(0, len(items), self.batch_size):
            batch = items[i:i + self.batch_size]
            
            # Process batch concurrently
            batch_results = await asyncio.gather(
                *[self._process_item(item, process_func) for item in batch],
                return_exceptions=True
            )
            
            # Filter out exceptions
            for result in batch_results:
                if not isinstance(result, Exception):
                    results.append(result)
            
            # Small delay between batches
            if i + self.batch_size < len(items):
                await asyncio.sleep(0.1)
        
        return results
    
    async def _process_item(self, item: Any, process_func: Callable):
        """Process single item with semaphore.
        
        Args:
            item: Item to process
            process_func: Async function to process item
            
        Returns:
            Processing result
        """
        async with self.semaphore:
            return await process_func(item)