"""
Directory sync - syncs with clearnet onion directories and lists.
"""

import asyncio
import json
import time
from typing import List, Set, Dict, Any, Optional
from datetime import datetime, timedelta
import logging

import aiohttp
from bs4 import BeautifulSoup

from src.discovery.harvester import OnionHarvester
from src.utils.logger import get_logger

logger = get_logger(__name__)


class DirectorySyncer:
    """Syncs with clearnet directories of onion services."""
    
    # Known clearnet directories (for research purposes only)
    KNOWN_DIRECTORIES = [
        # Note: These are examples. Use actual directories you have permission to access.
        "https://onion.ly",
        "https://onion.cab",
        "https://tor2web.org",
    ]
    
    # JSON endpoints that might contain onion addresses
    JSON_ENDPOINTS = [
        # Add any known JSON APIs here
    ]
    
    def __init__(
        self,
        harvester: Optional[OnionHarvester] = None,
        update_interval: int = 3600,  # 1 hour
        session_timeout: int = 30,
    ):
        """Initialize directory syncer.
        
        Args:
            harvester: Onion harvester instance
            update_interval: Interval between syncs in seconds
            session_timeout: HTTP request timeout in seconds
        """
        self.harvester = harvester or OnionHarvester()
        self.update_interval = update_interval
        self.session_timeout = session_timeout
        
        # Cache for directory contents
        self.cache: Dict[str, Dict[str, Any]] = {}
        self.last_sync: Dict[str, datetime] = {}
        
        # Statistics
        self.stats = {
            'directories_synced': 0,
            'onions_found': 0,
            'last_full_sync': None,
            'sync_errors': 0,
        }
    
    async def sync_all_directories(
        self,
        directories: Optional[List[str]] = None,
        force: bool = False,
    ) -> Set[str]:
        """Sync with all directories.
        
        Args:
            directories: List of directory URLs (uses default if None)
            force: Force sync even if recently updated
            
        Returns:
            Set of discovered onion addresses
        """
        directories = directories or self.KNOWN_DIRECTORIES
        all_discovered = set()
        
        for directory in directories:
            try:
                # Check if we need to sync
                if not force and not self._should_sync(directory):
                    logger.debug(f"Skipping {directory}, synced recently")
                    continue
                
                # Sync with directory
                discovered = await self._sync_directory(directory)
                all_discovered.update(discovered)
                
                self.stats['directories_synced'] += 1
                self.stats['onions_found'] += len(discovered)
                
                logger.info(f"Synced {directory}: found {len(discovered)} onions")
                
            except Exception as e:
                self.stats['sync_errors'] += 1
                logger.error(f"Error syncing directory {directory}: {e}")
        
        self.stats['last_full_sync'] = datetime.now().isoformat()
        return all_discovered
    
    async def _sync_directory(self, directory_url: str) -> Set[str]:
        """Sync with a single directory.
        
        Args:
            directory_url: Directory URL
            
        Returns:
            Set of discovered onion addresses
        """
        discovered = set()
        
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=self.session_timeout)) as session:
            try:
                # Try to fetch the directory
                async with session.get(directory_url) as response:
                    if response.status == 200:
                        content = await response.text()
                        content_type = response.headers.get('Content-Type', '')
                        
                        # Update cache
                        self.cache[directory_url] = {
                            'content': content[:10000],  # Store first 10k chars
                            'timestamp': datetime.now(),
                            'size': len(content),
                        }
                        
                        # Extract onion addresses
                        if 'json' in content_type.lower():
                            # Try to parse as JSON
                            try:
                                data = await response.json()
                                discovered.update(self._extract_from_json(data))
                            except json.JSONDecodeError:
                                # Fall back to text extraction
                                discovered.update(self.harvester.extract_from_text(content))
                        else:
                            # Parse as HTML/text
                            discovered.update(self.harvester.extract_from_html(content, directory_url))
                        
                        # Update last sync time
                        self.last_sync[directory_url] = datetime.now()
                    
                    else:
                        logger.warning(f"Directory {directory_url} returned {response.status}")
            
            except asyncio.TimeoutError:
                logger.error(f"Timeout syncing directory {directory_url}")
            except Exception as e:
                logger.error(f"Error fetching directory {directory_url}: {e}")
        
        return discovered
    
    def _extract_from_json(self, data: Any) -> Set[str]:
        """Extract onion addresses from JSON data.
        
        Args:
            data: JSON data (dict, list, etc.)
            
        Returns:
            Set of onion addresses
        """
        discovered = set()
        
        def _traverse(obj):
            if isinstance(obj, dict):
                for key, value in obj.items():
                    # Check both keys and values
                    if isinstance(key, str):
                        discovered.update(self.harvester.extract_from_text(key))
                    _traverse(value)
            elif isinstance(obj, list):
                for item in obj:
                    _traverse(item)
            elif isinstance(obj, str):
                discovered.update(self.harvester.extract_from_text(obj))
        
        _traverse(data)
        return discovered
    
    def _should_sync(self, directory_url: str) -> bool:
        """Check if directory should be synced.
        
        Args:
            directory_url: Directory URL
            
        Returns:
            True if should sync
        """
        if directory_url not in self.last_sync:
            return True
        
        last_sync = self.last_sync[directory_url]
        return (datetime.now() - last_sync).total_seconds() > self.update_interval
    
    async def sync_json_endpoints(
        self,
        endpoints: Optional[List[str]] = None,
    ) -> Set[str]:
        """Sync with JSON endpoints.
        
        Args:
            endpoints: List of JSON endpoint URLs
            
        Returns:
            Set of discovered onion addresses
        """
        endpoints = endpoints or self.JSON_ENDPOINTS
        all_discovered = set()
        
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=self.session_timeout)) as session:
            for endpoint in endpoints:
                try:
                    async with session.get(endpoint) as response:
                        if response.status == 200:
                            data = await response.json()
                            discovered = self._extract_from_json(data)
                            all_discovered.update(discovered)
                            
                            logger.info(f"Synced JSON endpoint {endpoint}: found {len(discovered)} onions")
                        else:
                            logger.warning(f"JSON endpoint {endpoint} returned {response.status}")
                
                except Exception as e:
                    logger.error(f"Error syncing JSON endpoint {endpoint}: {e}")
        
        return all_discovered
    
    def get_directory_cache(self, directory_url: str) -> Optional[Dict[str, Any]]:
        """Get cached directory content.
        
        Args:
            directory_url: Directory URL
            
        Returns:
            Cached content or None
        """
        return self.cache.get(directory_url)
    
    def clear_cache(self, older_than: Optional[timedelta] = None):
        """Clear directory cache.
        
        Args:
            older_than: Clear cache entries older than this
        """
        if older_than:
            cutoff = datetime.now() - older_than
            to_delete = []
            
            for url, cache_entry in self.cache.items():
                if cache_entry['timestamp'] < cutoff:
                    to_delete.append(url)
            
            for url in to_delete:
                del self.cache[url]
            
            logger.info(f"Cleared {len(to_delete)} cache entries older than {older_than}")
        else:
            self.cache.clear()
            logger.info("Cleared all directory cache")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get syncer statistics.
        
        Returns:
            Dictionary with statistics
        """
        stats = self.stats.copy()
        stats['cached_directories'] = len(self.cache)
        stats['directories_tracked'] = len(self.last_sync)
        return stats


class FeedMonitor:
    """Monitors RSS/Atom feeds for onion address mentions."""
    
    def __init__(
        self,
        harvester: Optional[OnionHarvester] = None,
        update_interval: int = 1800,  # 30 minutes
    ):
        """Initialize feed monitor.
        
        Args:
            harvester: Onion harvester instance
            update_interval: Interval between checks in seconds
        """
        self.harvester = harvester or OnionHarvester()
        self.update_interval = update_interval
        
        # Feed cache
        self.feed_cache: Dict[str, Set[str]] = {}
        self.last_check: Dict[str, datetime] = {}
        
        # Statistics
        self.stats = {
            'feeds_monitored': 0,
            'items_processed': 0,
            'onions_found': 0,
        }
    
    async def monitor_feeds(
        self,
        feed_urls: List[str],
    ) -> Set[str]:
        """Monitor RSS/Atom feeds.
        
        Args:
            feed_urls: List of feed URLs
            
        Returns:
            Set of discovered onion addresses
        """
        all_discovered = set()
        
        for feed_url in feed_urls:
            try:
                discovered = await self._check_feed(feed_url)
                all_discovered.update(discovered)
                
                self.stats['feeds_monitored'] += 1
                self.stats['onions_found'] += len(discovered)
                
                if discovered:
                    logger.info(f"Feed {feed_url}: found {len(discovered)} onions")
            
            except Exception as e:
                logger.error(f"Error monitoring feed {feed_url}: {e}")
        
        return all_discovered
    
    async def _check_feed(self, feed_url: str) -> Set[str]:
        """Check a single feed.
        
        Args:
            feed_url: Feed URL
            
        Returns:
            Set of discovered onion addresses
        """
        discovered = set()
        
        try:
            # Import feedparser (optional dependency)
            import feedparser
            
            # Parse feed
            feed = feedparser.parse(feed_url)
            
            if feed.bozo:  # Check for parsing errors
                logger.warning(f"Error parsing feed {feed_url}: {feed.bozo_exception}")
                return discovered
            
            # Get existing item IDs
            existing_ids = self.feed_cache.get(feed_url, set())
            new_ids = set()
            
            # Process feed items
            for entry in feed.entries:
                item_id = entry.get('id', entry.get('link', ''))
                new_ids.add(item_id)
                
                # Check if we've seen this item before
                if item_id in existing_ids:
                    continue
                
                # Extract onion addresses from title and content
                title = entry.get('title', '')
                summary = entry.get('summary', '')
                content = entry.get('content', [{}])[0].get('value', '') if entry.get('content') else ''
                
                # Combine all text
                text = f"{title} {summary} {content}"
                
                # Extract onion addresses
                item_onions = self.harvester.extract_from_text(text)
                discovered.update(item_onions)
                
                self.stats['items_processed'] += 1
            
            # Update cache
            self.feed_cache[feed_url] = new_ids
            self.last_check[feed_url] = datetime.now()
        
        except ImportError:
            logger.warning("feedparser not installed. Install with: pip install feedparser")
        except Exception as e:
            logger.error(f"Error checking feed {feed_url}: {e}")
        
        return discovered
    
    def get_stats(self) -> Dict[str, Any]:
        """Get feed monitor statistics.
        
        Returns:
            Dictionary with statistics
        """
        stats = self.stats.copy()
        stats['feeds_tracked'] = len(self.feed_cache)
        return stats