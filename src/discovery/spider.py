"""
Link spider - crawls dark web sites and extracts links.
"""

import asyncio
import time
import random
from typing import List, Set, Dict, Any, Optional, Tuple
from urllib.parse import urlparse, urljoin
import logging
from dataclasses import dataclass
from enum import Enum

from src.core.tor_manager import TorManager, Circuit
from src.discovery.harvester import OnionHarvester
from src.utils.logger import get_logger

logger = get_logger(__name__)


class SpiderState(Enum):
    """State of the spider."""
    IDLE = "idle"
    CRAWLING = "crawling"
    PAUSED = "paused"
    STOPPED = "stopped"


@dataclass
class CrawlResult:
    """Result of crawling a URL."""
    url: str
    success: bool
    status_code: Optional[int] = None
    content: Optional[str] = None
    content_type: Optional[str] = None
    error: Optional[str] = None
    discovered_links: Set[str] = None
    redirects: List[str] = None
    load_time: float = 0.0
    content_hash: Optional[str] = None
    
    def __post_init__(self):
        if self.discovered_links is None:
            self.discovered_links = set()
        if self.redirects is None:
            self.redirects = []


class LinkSpider:
    """Spider that crawls dark web sites to discover new links."""
    
    def __init__(
        self,
        tor_manager: TorManager,
        max_depth: int = 3,
        max_pages_per_site: int = 50,
        request_delay: Tuple[float, float] = (1.0, 3.0),
        timeout: int = 30,
        user_agent: Optional[str] = None,
        respect_robots_txt: bool = True,
    ):
        """Initialize the spider.
        
        Args:
            tor_manager: Tor manager instance
            max_depth: Maximum crawl depth
            max_pages_per_site: Maximum pages to crawl per site
            request_delay: Min and max delay between requests in seconds
            timeout: Request timeout in seconds
            user_agent: User agent string
            respect_robots_txt: Whether to respect robots.txt
        """
        self.tor_manager = tor_manager
        self.max_depth = max_depth
        self.max_pages_per_site = max_pages_per_site
        self.request_delay = request_delay
        self.timeout = timeout
        self.user_agent = user_agent or self._get_random_user_agent()
        self.respect_robots_txt = respect_robots_txt
        
        self.harvester = OnionHarvester()
        self.state = SpiderState.IDLE
        self.circuit: Optional[Circuit] = None
        
        # Statistics
        self.stats = {
            'pages_crawled': 0,
            'links_discovered': 0,
            'errors': 0,
            'start_time': None,
            'circuits_used': 0,
        }
        
        # Rate limiting
        self.last_request_time = 0
        self.request_count = 0
        
    def _get_random_user_agent(self) -> str:
        """Get random user agent."""
        user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15',
            'Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/119.0',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/119.0',
        ]
        return random.choice(user_agents)
    
    async def crawl_site(
        self, 
        start_url: str, 
        depth: int = 1,
        known_urls: Optional[Set[str]] = None
    ) -> Dict[str, CrawlResult]:
        """Crawl a site starting from the given URL.
        
        Args:
            start_url: Starting URL
            depth: Maximum crawl depth
            known_urls: Set of already known URLs to avoid
            
        Returns:
            Dictionary of URL -> CrawlResult
        """
        if self.state != SpiderState.IDLE:
            raise RuntimeError(f"Spider is not idle (state: {self.state})")
        
        self.state = SpiderState.CRAWLING
        self.stats['start_time'] = time.time()
        self.stats['pages_crawled'] = 0
        self.stats['links_discovered'] = 0
        self.stats['errors'] = 0
        
        known_urls = known_urls or set()
        crawl_results: Dict[str, CrawlResult] = {}
        queue = [(start_url, 0)]  # (url, depth)
        visited = set()
        
        try:
            # Get fresh circuit for this crawl session
            self.circuit = self.tor_manager.get_circuit(require_fresh=True)
            if not self.circuit:
                raise RuntimeError("Failed to get Tor circuit")
            
            self.stats['circuits_used'] += 1
            
            while queue and len(visited) < self.max_pages_per_site:
                if self.state != SpiderState.CRAWLING:
                    break
                
                url, current_depth = queue.pop(0)
                
                # Skip if already visited or exceeds depth
                if url in visited or current_depth > depth:
                    continue
                
                # Check if it's an onion URL
                if not self.harvester._is_onion_url(url):
                    logger.warning(f"Skipping non-onion URL: {url}")
                    continue
                
                # Rate limiting
                await self._rate_limit()
                
                # Crawl the page
                result = await self._crawl_page(url)
                visited.add(url)
                crawl_results[url] = result
                
                self.stats['pages_crawled'] += 1
                if not result.success:
                    self.stats['errors'] += 1
                
                # Extract links if successful
                if result.success and result.content and current_depth < depth:
                    discovered = self.harvester.extract_from_html(
                        result.content, 
                        base_url=url
                    )
                    
                    # Filter to onion URLs only
                    onion_links = {
                        link for link in discovered 
                        if self.harvester._is_onion_url(link)
                    }
                    
                    result.discovered_links = onion_links
                    self.stats['links_discovered'] += len(onion_links)
                    
                    # Add new links to queue
                    for link in onion_links:
                        if link not in visited and link not in [u for u, _ in queue]:
                            queue.append((link, current_depth + 1))
                
                # Rotate circuit periodically
                if self.stats['pages_crawled'] % 10 == 0:
                    await self._rotate_circuit()
        
        except Exception as e:
            logger.error(f"Error during crawl: {e}")
            self.stats['errors'] += 1
        finally:
            self.state = SpiderState.IDLE
            self.circuit = None
        
        return crawl_results
    
    async def _crawl_page(self, url: str) -> CrawlResult:
        """Crawl a single page.
        
        Args:
            url: URL to crawl
            
        Returns:
            CrawlResult with page data
        """
        start_time = time.time()
        result = CrawlResult(url=url, success=False)
        
        try:
            # Use HTTP session for simple requests
            async with self.tor_manager.get_http_session(self.circuit) as session:
                # Set timeout
                session.timeout = self.timeout
                
                # Add headers
                headers = {
                    'User-Agent': self.user_agent,
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                    'Accept-Language': 'en-US,en;q=0.5',
                    'Accept-Encoding': 'gzip, deflate',
                    'Connection': 'keep-alive',
                    'Upgrade-Insecure-Requests': '1',
                }
                
                # Make request
                response = session.get(
                    url, 
                    headers=headers, 
                    allow_redirects=True,
                    timeout=self.timeout
                )
                
                result.status_code = response.status_code
                result.content_type = response.headers.get('Content-Type', '')
                
                # Check if successful
                if response.status_code == 200:
                    result.success = True
                    result.content = response.text
                    result.content_hash = self.harvester.calculate_content_hash(response.text)
                    
                    # Extract redirect history
                    if response.history:
                        result.redirects = [resp.url for resp in response.history]
                    
                    logger.debug(f"Crawled {url} - {len(response.text)} bytes")
                else:
                    result.error = f"HTTP {response.status_code}"
                    logger.warning(f"Failed to crawl {url}: {response.status_code}")
        
        except Exception as e:
            result.error = str(e)
            logger.error(f"Error crawling {url}: {e}")
            
            # Mark circuit as dead if it's a connection error
            if self.circuit and any(err in str(e).lower() for err in 
                                   ['connection', 'timeout', 'reset', 'refused']):
                self.tor_manager.mark_circuit_dead(self.circuit.id)
                self.circuit = None
        
        finally:
            result.load_time = time.time() - start_time
        
        return result
    
    async def _crawl_page_with_browser(self, url: str) -> CrawlResult:
        """Crawl a single page using headless browser (for JavaScript-heavy sites).
        
        Args:
            url: URL to crawl
            
        Returns:
            CrawlResult with page data
        """
        from selenium.common.exceptions import TimeoutException, WebDriverException
        
        start_time = time.time()
        result = CrawlResult(url=url, success=False)
        driver = None
        
        try:
            # Get browser instance
            driver = self.tor_manager.get_browser(self.circuit)
            
            # Set page load timeout
            driver.set_page_load_timeout(self.timeout)
            
            # Navigate to URL
            driver.get(url)
            
            # Wait for page to load
            time.sleep(2)  # Simple wait, could be improved
            
            # Get page source
            result.content = driver.page_source
            result.success = True
            result.content_hash = self.harvester.calculate_content_hash(driver.page_source)
            
            # Get current URL (after redirects)
            current_url = driver.current_url
            if current_url != url:
                result.redirects = [current_url]
            
            logger.debug(f"Crawled {url} with browser - {len(result.content)} bytes")
        
        except TimeoutException:
            result.error = "Page load timeout"
            logger.warning(f"Timeout crawling {url}")
        except WebDriverException as e:
            result.error = str(e)
            logger.error(f"Browser error crawling {url}: {e}")
        except Exception as e:
            result.error = str(e)
            logger.error(f"Error crawling {url} with browser: {e}")
        finally:
            if driver:
                driver.quit()
            
            result.load_time = time.time() - start_time
        
        return result
    
    async def _rate_limit(self):
        """Rate limiting to avoid detection."""
        # Calculate delay
        min_delay, max_delay = self.request_delay
        delay = random.uniform(min_delay, max_delay)
        
        # Apply jitter
        jitter = random.uniform(-0.2, 0.2) * delay
        delay = max(0.1, delay + jitter)  # Ensure positive delay
        
        # Wait if needed
        elapsed = time.time() - self.last_request_time
        if elapsed < delay:
            await asyncio.sleep(delay - elapsed)
        
        self.last_request_time = time.time()
        self.request_count += 1
    
    async def _rotate_circuit(self):
        """Rotate Tor circuit for anonymity."""
        if self.circuit:
            logger.debug(f"Rotating circuit {self.circuit.id}")
            self.tor_manager.mark_circuit_dead(self.circuit.id)
        
        self.circuit = self.tor_manager.get_circuit(require_fresh=True)
        if self.circuit:
            self.stats['circuits_used'] += 1
            logger.debug(f"Using new circuit {self.circuit.id}")
        else:
            logger.warning("Failed to get new circuit")
    
    def pause(self):
        """Pause the spider."""
        if self.state == SpiderState.CRAWLING:
            self.state = SpiderState.PAUSED
            logger.info("Spider paused")
    
    def resume(self):
        """Resume the spider."""
        if self.state == SpiderState.PAUSED:
            self.state = SpiderState.CRAWLING
            logger.info("Spider resumed")
    
    def stop(self):
        """Stop the spider."""
        self.state = SpiderState.STOPPED
        logger.info("Spider stopped")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get spider statistics.
        
        Returns:
            Dictionary with statistics
        """
        stats = self.stats.copy()
        
        if stats['start_time']:
            elapsed = time.time() - stats['start_time']
            stats['elapsed_time'] = elapsed
            if stats['pages_crawled'] > 0:
                stats['pages_per_second'] = stats['pages_crawled'] / elapsed
            else:
                stats['pages_per_second'] = 0
        
        stats['state'] = self.state.value
        stats['circuit_active'] = self.circuit is not None
        stats['request_count'] = self.request_count
        
        return stats


class BatchSpider:
    """Manages multiple spiders for parallel crawling."""
    
    def __init__(
        self,
        tor_manager: TorManager,
        max_concurrent: int = 3,
        spider_config: Optional[Dict[str, Any]] = None,
    ):
        """Initialize batch spider.
        
        Args:
            tor_manager: Tor manager instance
            max_concurrent: Maximum concurrent spiders
            spider_config: Configuration for individual spiders
        """
        self.tor_manager = tor_manager
        self.max_concurrent = max_concurrent
        self.spider_config = spider_config or {}
        
        self.spiders: List[LinkSpider] = []
        self.tasks: List[asyncio.Task] = []
        self.results: Dict[str, Dict[str, CrawlResult]] = {}
        
    async def crawl_multiple(
        self,
        urls: List[str],
        depth: int = 1,
        known_urls: Optional[Set[str]] = None
    ) -> Dict[str, Dict[str, CrawlResult]]:
        """Crawl multiple sites in parallel.
        
        Args:
            urls: List of starting URLs
            depth: Maximum crawl depth per site
            known_urls: Set of already known URLs
            
        Returns:
            Dictionary of domain -> crawl results
        """
        known_urls = known_urls or set()
        self.results = {}
        
        # Create spiders
        self.spiders = [
            LinkSpider(self.tor_manager, **self.spider_config)
            for _ in range(min(self.max_concurrent, len(urls)))
        ]
        
        # Create tasks
        self.tasks = []
        for i, url in enumerate(urls):
            spider_idx = i % len(self.spiders)
            task = asyncio.create_task(
                self._crawl_with_spider(self.spiders[spider_idx], url, depth, known_urls)
            )
            self.tasks.append(task)
        
        # Wait for all tasks to complete
        await asyncio.gather(*self.tasks, return_exceptions=True)
        
        return self.results
    
    async def _crawl_with_spider(
        self,
        spider: LinkSpider,
        url: str,
        depth: int,
        known_urls: Set[str]
    ):
        """Crawl with a specific spider.
        
        Args:
            spider: Spider instance
            url: URL to crawl
            depth: Maximum crawl depth
            known_urls: Set of known URLs
        """
        try:
            results = await spider.crawl_site(url, depth, known_urls)
            self.results[url] = results
            
            # Extract domain for organization
            parsed = urlparse(url)
            domain = parsed.netloc
            
            logger.info(
                f"Completed crawl of {domain}: "
                f"{len(results)} pages, "
                f"{sum(len(r.discovered_links) for r in results.values() if r.discovered_links)} links"
            )
        
        except Exception as e:
            logger.error(f"Error in spider for {url}: {e}")
            self.results[url] = {}
    
    def get_overall_stats(self) -> Dict[str, Any]:
        """Get overall statistics from all spiders.
        
        Returns:
            Dictionary with aggregated statistics
        """
        stats = {
            'total_pages_crawled': 0,
            'total_links_discovered': 0,
            'total_errors': 0,
            'active_spiders': 0,
            'total_circuits_used': 0,
        }
        
        for spider in self.spiders:
            spider_stats = spider.get_stats()
            stats['total_pages_crawled'] += spider_stats.get('pages_crawled', 0)
            stats['total_links_discovered'] += spider_stats.get('links_discovered', 0)
            stats['total_errors'] += spider_stats.get('errors', 0)
            stats['total_circuits_used'] += spider_stats.get('circuits_used', 0)
            
            if spider.state == SpiderState.CRAWLING:
                stats['active_spiders'] += 1
        
        return stats
    
    def stop_all(self):
        """Stop all spiders."""
        for spider in self.spiders:
            spider.stop()
        
        for task in self.tasks:
            if not task.done():
                task.cancel()
        
        logger.info("All spiders stopped")