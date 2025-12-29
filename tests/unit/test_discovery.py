"""
Tests for discovery components.
"""

import pytest
import asyncio
from unittest.mock import AsyncMock, Mock, patch
from src.discovery.harvester import OnionHarvester
from src.discovery.spider import LinkSpider, CrawlResult
from src.discovery.orchestrator import DiscoveryOrchestrator, DiscoveryConfig, DiscoveryMode


class TestOnionHarvester:
    """Test onion harvester."""
    
    def test_extract_from_html(self):
        """Test extracting onion addresses from HTML."""
        harvester = OnionHarvester()
        
        html = """
        <html>
            <body>
                <a href="http://abcdefghijklmnop.onion/page">Link 1</a>
                <a href="https://3g2upl4pq6kufc4m.onion/page2">Link 2</a>
                <p>Check out http://abcdefghijklmnop.onion</p>
                <script src="http://3g2upl4pq6kufc4m.onion/script.js"></script>
            </body>
        </html>
        """
        
        discovered = harvester.extract_from_html(html)
        assert len(discovered) >= 3  # Should find at least 3 onion addresses
        assert any("abcdefghijklmnop.onion" in url for url in discovered)
        assert any("3g2upl4pq6kufc4m.onion" in url for url in discovered)
    
    def test_extract_from_text(self):
        """Test extracting onion addresses from text."""
        harvester = OnionHarvester()
        
        text = """
        Check these sites:
        http://abcdefghijklmnop.onion
        https://3g2upl4pq6kufc4m.onion/page
        Also: bcdefghijklmnopqr.st (without scheme)
        """
        
        discovered = harvester.extract_from_text(text)
        assert len(discovered) >= 2
        assert any("abcdefghijklmnop.onion" in url for url in discovered)
        assert any("3g2upl4pq6kufc4m.onion" in url for url in discovered)
    
    def test_validate_onion_url(self):
        """Test onion URL validation."""
        harvester = OnionHarvester()
        
        # Valid v2 onion (16 chars)
        assert harvester._is_onion_url("http://abcdefghijklmnop.onion")
        
        # Valid v3 onion (starts with 3, 16 chars for this example)
        assert harvester._is_onion_url("https://3g2upl4pq6kufc4m.onion")
        
        # Invalid URLs
        assert not harvester._is_onion_url("http://google.com")
        assert not harvester._is_onion_url("http://short.onion")
        assert not harvester._is_onion_url("not-a-url")


class TestLinkSpider:
    """Test link spider."""
    
    @pytest.fixture
    def mock_tor_manager(self):
        """Create mock Tor manager."""
        manager = Mock()
        manager.get_circuit.return_value = Mock(id="test-circuit")
        manager.get_http_session.return_value.__enter__.return_value = Mock()
        return manager
    
    @pytest.mark.asyncio
    async def test_crawl_site(self, mock_tor_manager):
        """Test crawling a site."""
        spider = LinkSpider(mock_tor_manager, max_depth=1)
        
        # Mock HTTP response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = """
        <html>
            <a href="http://test123456789012.onion">Link 1</a>
            <a href="http://test123456789013.onion">Link 2</a>
        </html>
        """
        mock_response.headers = {'Content-Type': 'text/html'}
        mock_response.history = []
        
        # Configure mock session
        mock_session = mock_tor_manager.get_http_session.return_value.__enter__.return_value
        mock_session.get.return_value = mock_response
        mock_session.timeout = 30
        
        # Test crawl
        results = await spider.crawl_site("http://start123456789012.onion", depth=1)
        
        assert len(results) > 0
        assert "http://start123456789012.onion" in results
        
        # Check that links were discovered
        result = results["http://start123456789012.onion"]
        assert result.success
        assert len(result.discovered_links) >= 2
    
    @pytest.mark.asyncio
    async def test_rate_limit(self, mock_tor_manager):
        """Test rate limiting."""
        spider = LinkSpider(mock_tor_manager, request_delay=(0.1, 0.2))
        
        start_time = asyncio.get_event_loop().time()
        await spider._rate_limit()
        end_time = asyncio.get_event_loop().time()
        
        # Should have delayed
        assert end_time - start_time >= 0.09  # Allow some tolerance


class TestDiscoveryOrchestrator:
    """Test discovery orchestrator."""
    
    @pytest.fixture
    def mock_components(self):
        """Create mock components."""
        tor_manager = Mock()
        database = Mock()
        
        # Mock database session
        mock_session = AsyncMock()
        database.get_session.return_value.__aenter__.return_value = mock_session
        
        # Mock repositories
        mock_site_repo = Mock()
        mock_site_repo.get_pending_sites.return_value = []
        mock_site_repo.create_or_update_site.return_value = Mock(id="test-site")
        
        return tor_manager, database, mock_session, mock_site_repo
    
    @pytest.mark.asyncio
    async def test_discover_crawl_mode(self, mock_components):
        """Test discovery in crawl mode."""
        tor_manager, database, mock_session, mock_site_repo = mock_components
        
        config = DiscoveryConfig(mode=DiscoveryMode.CRAWL, max_depth=1)
        orchestrator = DiscoveryOrchestrator(tor_manager, database, config)
        
        # Mock spider results
        with patch('src.discovery.orchestrator.BatchSpider') as mock_spider_class:
            mock_spider = AsyncMock()
            mock_spider.crawl_multiple.return_value = {
                'http://start.onion': {
                    'http://start.onion': CrawlResult(
                        url='http://start.onion',
                        success=True,
                        discovered_links={'http://new1.onion', 'http://new2.onion'}
                    )
                }
            }
            mock_spider.get_overall_stats.return_value = {
                'total_pages_crawled': 1,
                'total_links_discovered': 2,
            }
            mock_spider_class.return_value = mock_spider
            
            # Run discovery
            results = await orchestrator.discover(
                seed_urls=['http://start.onion'],
                known_urls=set()
            )
            
            assert results['sites_discovered'] > 0
            assert mock_spider.crawl_multiple.called
    
    @pytest.mark.asyncio
    async def test_continuous_discovery(self, mock_components):
        """Test continuous discovery."""
        tor_manager, database, mock_session, mock_site_repo = mock_components
        
        orchestrator = DiscoveryOrchestrator(tor_manager, database)
        
        # Mock discover method to return quickly
        with patch.object(orchestrator, 'discover', AsyncMock()) as mock_discover:
            # Start continuous discovery with short interval
            task = asyncio.create_task(orchestrator.start_continuous_discovery(interval=1))
            
            # Wait a bit
            await asyncio.sleep(0.5)
            
            # Stop
            await orchestrator.stop_continuous_discovery()
            
            # Clean up
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
            
            # Should have called discover at least once
            assert mock_discover.called