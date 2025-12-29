"""
Discovery orchestrator - coordinates all discovery components.
"""

import asyncio
import time
from typing import List, Set, Dict, Any, Optional
from datetime import datetime
from dataclasses import dataclass
from enum import Enum
import logging

from src.core.tor_manager import TorManager
from src.discovery.harvester import OnionHarvester
from src.discovery.spider import LinkSpider, BatchSpider
from src.discovery.listener import SocialListener, MultiChannelListener
from src.discovery.directory import DirectorySyncer, FeedMonitor
from src.storage.database import Database, SiteRepository, DiscoveryRepository, CrawlJobRepository
from src.utils.logger import get_logger

logger = get_logger(__name__)


class DiscoveryMode(Enum):
    """Discovery operation modes."""
    FULL = "full"           # Full discovery (all methods)
    CRAWL = "crawl"         # Only crawling
    LISTEN = "listen"       # Only listening
    SYNC = "sync"          # Only directory sync
    TARGETED = "targeted"  # Targeted discovery of specific sites


@dataclass
class DiscoveryConfig:
    """Configuration for discovery operations."""
    
    # Modes
    mode: DiscoveryMode = DiscoveryMode.FULL
    
    # Spider configuration
    max_depth: int = 2
    max_pages_per_site: int = 50
    max_concurrent_spiders: int = 3
    
    # Listener configuration
    monitor_telegram: bool = False
    monitor_irc: bool = False
    monitor_twitter: bool = False
    listener_check_interval: int = 300  # 5 minutes
    
    # Directory sync configuration
    sync_directories: bool = True
    sync_feeds: bool = False
    sync_interval: int = 3600  # 1 hour
    
    # General
    max_new_sites: int = 1000
    timeout: int = 3600  # 1 hour max


class DiscoveryOrchestrator:
    """Orchestrates all discovery components."""
    
    def __init__(
        self,
        tor_manager: TorManager,
        database: Database,
        config: Optional[DiscoveryConfig] = None,
    ):
        """Initialize discovery orchestrator.
        
        Args:
            tor_manager: Tor manager instance
            database: Database instance
            config: Discovery configuration
        """
        self.tor_manager = tor_manager
        self.database = database
        self.config = config or DiscoveryConfig()
        
        # Components
        self.harvester = OnionHarvester()
        self.spider: Optional[LinkSpider] = None
        self.batch_spider: Optional[BatchSpider] = None
        self.listener: Optional[MultiChannelListener] = None
        self.directory_syncer: Optional[DirectorySyncer] = None
        self.feed_monitor: Optional[FeedMonitor] = None
        
        # State
        self.running = False
        self.current_task: Optional[asyncio.Task] = None
        
        # Results
        self.results = {
            'sites_discovered': 0,
            'links_found': 0,
            'start_time': None,
            'end_time': None,
            'errors': 0,
        }
        
        # Repositories
        self.site_repo = SiteRepository(database)
        self.discovery_repo = DiscoveryRepository(database)
        self.crawl_repo = CrawlJobRepository(database)
    
    async def discover(
        self,
        seed_urls: Optional[List[str]] = None,
        known_urls: Optional[Set[str]] = None,
    ) -> Dict[str, Any]:
        """Run discovery operation.
        
        Args:
            seed_urls: Starting URLs for crawling
            known_urls: Already known URLs to avoid
            
        Returns:
            Discovery results
        """
        if self.running:
            raise RuntimeError("Discovery already running")
        
        self.running = True
        self.results = {
            'sites_discovered': 0,
            'links_found': 0,
            'start_time': datetime.now().isoformat(),
            'end_time': None,
            'errors': 0,
        }
        
        all_discovered = set()
        
        try:
            # Get seed URLs from database if not provided
            if not seed_urls:
                async with self.database.get_session() as session:
                    # Get active sites to crawl
                    sites = await self.site_repo.get_pending_sites(session, limit=100)
                    seed_urls = [site.onion_address for site in sites]
            
            known_urls = known_urls or await self._get_known_urls()
            
            # Run discovery based on mode
            if self.config.mode in [DiscoveryMode.FULL, DiscoveryMode.CRAWL]:
                discovered = await self._run_crawling(seed_urls, known_urls)
                all_discovered.update(discovered)
            
            if self.config.mode in [DiscoveryMode.FULL, DiscoveryMode.LISTEN]:
                discovered = await self._run_listening()
                all_discovered.update(discovered)
            
            if self.config.mode in [DiscoveryMode.FULL, DiscoveryMode.SYNC]:
                discovered = await self._run_syncing()
                all_discovered.update(discovered)
            
            # Store results in database
            await self._store_discoveries(all_discovered)
            
            self.results['sites_discovered'] = len(all_discovered)
            self.results['end_time'] = datetime.now().isoformat()
            
            logger.info(f"Discovery complete: found {len(all_discovered)} new sites")
        
        except Exception as e:
            self.results['errors'] += 1
            logger.error(f"Error during discovery: {e}")
            raise
        
        finally:
            self.running = False
        
        return self.results
    
    async def _run_crawling(
        self,
        seed_urls: List[str],
        known_urls: Set[str],
    ) -> Set[str]:
        """Run crawling discovery.
        
        Args:
            seed_urls: Starting URLs
            known_urls: Known URLs to avoid
            
        Returns:
            Set of discovered onion addresses
        """
        discovered = set()
        
        logger.info(f"Starting crawling with {len(seed_urls)} seed URLs")
        
        # Initialize batch spider
        spider_config = {
            'max_depth': self.config.max_depth,
            'max_pages_per_site': self.config.max_pages_per_site,
        }
        
        self.batch_spider = BatchSpider(
            self.tor_manager,
            max_concurrent=self.config.max_concurrent_spiders,
            spider_config=spider_config,
        )
        
        try:
            # Run crawling
            results = await self.batch_spider.crawl_multiple(
                seed_urls,
                depth=self.config.max_depth,
                known_urls=known_urls,
            )
            
            # Extract discovered URLs
            for url, crawl_results in results.items():
                for result in crawl_results.values():
                    if result.discovered_links:
                        discovered.update(result.discovered_links)
            
            # Get statistics
            spider_stats = self.batch_spider.get_overall_stats()
            logger.info(
                f"Crawling complete: "
                f"{spider_stats['total_pages_crawled']} pages, "
                f"{spider_stats['total_links_discovered']} links"
            )
        
        finally:
            self.batch_spider = None
        
        return discovered
    
    async def _run_listening(self) -> Set[str]:
        """Run social listening discovery.
        
        Returns:
            Set of discovered onion addresses
        """
        discovered = set()
        
        # Note: Social listening requires API keys and configuration
        # For now, we'll just log that it's not configured
        if (self.config.monitor_telegram or 
            self.config.monitor_irc or 
            self.config.monitor_twitter):
            
            logger.info("Social listening is enabled but not fully implemented")
            # TODO: Implement social listening with actual configuration
        
        return discovered
    
    async def _run_syncing(self) -> Set[str]:
        """Run directory syncing discovery.
        
        Returns:
            Set of discovered onion addresses
        """
        discovered = set()
        
        if self.config.sync_directories:
            logger.info("Syncing with directories...")
            
            self.directory_syncer = DirectorySyncer(
                self.harvester,
                update_interval=self.config.sync_interval,
            )
            
            try:
                dir_discovered = await self.directory_syncer.sync_all_directories()
                discovered.update(dir_discovered)
                
                stats = self.directory_syncer.get_stats()
                logger.info(
                    f"Directory sync complete: "
                    f"{stats['directories_synced']} directories, "
                    f"{stats['onions_found']} onions"
                )
            
            finally:
                self.directory_syncer = None
        
        if self.config.sync_feeds:
            logger.info("Monitoring feeds...")
            
            self.feed_monitor = FeedMonitor(
                self.harvester,
                update_interval=self.config.sync_interval,
            )
            
            # TODO: Add feed URLs from configuration
            feed_urls = []  # Add actual feed URLs
            
            try:
                feed_discovered = await self.feed_monitor.monitor_feeds(feed_urls)
                discovered.update(feed_discovered)
                
                stats = self.feed_monitor.get_stats()
                logger.info(
                    f"Feed monitoring complete: "
                    f"{stats['feeds_monitored']} feeds, "
                    f"{stats['onions_found']} onions"
                )
            
            finally:
                self.feed_monitor = None
        
        return discovered
    
    async def _get_known_urls(self) -> Set[str]:
        """Get known URLs from database.
        
        Returns:
            Set of known onion addresses
        """
        known_urls = set()
        
        async with self.database.get_session() as session:
            # Get all sites from database
            stmt = "SELECT onion_address FROM sites"
            result = await session.execute(stmt)
            rows = result.fetchall()
            
            for row in rows:
                known_urls.add(row[0])
        
        logger.debug(f"Loaded {len(known_urls)} known URLs from database")
        return known_urls
    
    async def _store_discoveries(self, discovered_urls: Set[str]):
        """Store discovered URLs in database.
        
        Args:
            discovered_urls: Set of discovered onion addresses
        """
        if not discovered_urls:
            return
        
        async with self.database.get_session() as session:
            for url in discovered_urls:
                try:
                    # Create or update site
                    site = await self.site_repo.create_or_update_site(
                        session,
                        onion_address=url,
                        status='discovered',
                    )
                    
                    # Create discovery result
                    await self.discovery_repo.create_discovery_result(
                        session,
                        site_id=site.id,
                        discovery_method='crawl',  # TODO: Track actual method
                        source_url=None,  # TODO: Track source
                        confidence=0.5,
                    )
                    
                except Exception as e:
                    self.results['errors'] += 1
                    logger.error(f"Error storing discovery {url}: {e}")
            
            await session.commit()
        
        logger.info(f"Stored {len(discovered_urls)} discoveries in database")
    
    async def start_continuous_discovery(
        self,
        interval: int = 3600,  # 1 hour
    ):
        """Start continuous discovery in background.
        
        Args:
            interval: Interval between discovery runs in seconds
        """
        if self.running:
            raise RuntimeError("Discovery already running")
        
        self.running = True
        
        async def _continuous_loop():
            while self.running:
                try:
                    logger.info("Starting scheduled discovery run")
                    
                    await self.discover()
                    
                    logger.info(f"Discovery complete. Next run in {interval} seconds")
                    
                    # Wait for next run
                    for _ in range(interval):
                        if not self.running:
                            break
                        await asyncio.sleep(1)
                
                except Exception as e:
                    logger.error(f"Error in continuous discovery: {e}")
                    
                    # Wait before retry
                    await asyncio.sleep(300)  # 5 minutes
        
        self.current_task = asyncio.create_task(_continuous_loop())
        logger.info(f"Started continuous discovery with {interval} second interval")
    
    async def stop_continuous_discovery(self):
        """Stop continuous discovery."""
        self.running = False
        
        if self.current_task and not self.current_task.done():
            self.current_task.cancel()
            try:
                await self.current_task
            except asyncio.CancelledError:
                pass
        
        if self.batch_spider:
            self.batch_spider.stop_all()
        
        if self.listener:
            await self.listener.stop_monitoring()
        
        logger.info("Stopped continuous discovery")
    
    def get_status(self) -> Dict[str, Any]:
        """Get orchestrator status.
        
        Returns:
            Dictionary with status information
        """
        status = {
            'running': self.running,
            'mode': self.config.mode.value,
            'results': self.results.copy(),
        }
        
        # Add component status
        if self.batch_spider:
            status['batch_spider'] = self.batch_spider.get_overall_stats()
        
        if self.listener:
            status['listener'] = self.listener.get_listener_stats()
        
        if self.directory_syncer:
            status['directory_syncer'] = self.directory_syncer.get_stats()
        
        if self.feed_monitor:
            status['feed_monitor'] = self.feed_monitor.get_stats()
        
        return status