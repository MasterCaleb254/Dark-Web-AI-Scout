"""
Full pipeline integration tests with mock Tor.
"""

import asyncio
import pytest
import json
from datetime import datetime, timedelta
from unittest.mock import patch, AsyncMock, MagicMock

from src.core.tor_manager import TorManager
from src.discovery.harvester import OnionHarvester
from src.discovery.spider import LinkSpider, BatchSpider
from src.discovery.orchestrator import DiscoveryOrchestrator, DiscoveryConfig
from src.classification.pipeline import ClassificationPipeline
from src.classification.storage import ClassificationStorage
from src.storage.database import Database
from src.utils.config import DatabaseConfig

from tests.mock_tor import MockTorManager, MockTorServer, TestDataGenerator


class TestFullPipeline:
    """Test the complete discovery -> classification pipeline."""
    
    @pytest.fixture
    async def mock_tor_manager(self):
        """Create mock Tor manager."""
        manager = MockTorManager()
        manager.start()
        yield manager
    
    @pytest.fixture
    async def mock_database(self):
        """Create mock database."""
        db = MagicMock(spec=Database)
        
        # Mock session
        mock_session = AsyncMock()
        db.get_session.return_value.__aenter__.return_value = mock_session
        
        # Mock repositories
        db.site_repo = MagicMock()
        db.discovery_repo = MagicMock()
        db.crawl_repo = MagicMock()
        
        yield db
    
    @pytest.fixture
    def sample_sites(self):
        """Generate sample sites for testing."""
        generator = TestDataGenerator()
        
        return [
            {
                'url': 'http://forum-test.onion',
                'content': generator.generate_forum_page(),
                'expected_category': 'forum',
            },
            {
                'url': 'http://market-test.onion',
                'content': generator.generate_market_page(),
                'expected_category': 'market',
            },
            {
                'url': 'http://scam-test.onion',
                'content': generator.generate_scam_page(),
                'expected_category': 'scam',
            },
            {
                'url': 'http://library-test.onion',
                'content': generator.generate_library_page(),
                'expected_category': 'library',
            },
        ]
    
    @pytest.mark.asyncio
    async def test_discovery_classification_integration(self, mock_tor_manager, mock_database, sample_sites):
        """Test integrated discovery and classification."""
        
        # Setup
        config = DiscoveryConfig(mode='crawl', max_depth=1, max_pages_per_site=10)
        orchestrator = DiscoveryOrchestrator(mock_tor_manager, mock_database, config)
        
        # Mock spider results
        with patch.object(orchestrator, '_run_crawling') as mock_crawl:
            # Simulate discovering the sample sites
            discovered_urls = {site['url'] for site in sample_sites}
            mock_crawl.return_value = discovered_urls
            
            # Run discovery
            results = await orchestrator.discover(
                seed_urls=['http://start.onion'],
                known_urls=set()
            )
            
            assert results['sites_discovered'] == len(sample_sites)
        
        # Test classification on discovered content
        pipeline = ClassificationPipeline()
        
        classification_results = []
        for site in sample_sites:
            result = await pipeline.process(
                url=site['url'],
                content=site['content'],
                content_type_hint='text/html',
            )
            
            classification_results.append(result)
            
            # Verify safety check passed
            assert result.is_safe
            
            # Verify classification is reasonable
            if result.classification_result:
                category = result.classification_result.category.value
                # Check if classification matches expected (allowing for some error)
                assert category in ['forum', 'market', 'scam', 'library', 'service', 'other']
        
        # Verify we got results for all sites
        assert len(classification_results) == len(sample_sites)
        
        # Check pipeline statistics
        stats = pipeline.get_pipeline_stats()
        assert stats['processed'] == len(sample_sites)
        assert stats['classified'] == len(sample_sites)
    
    @pytest.mark.asyncio
    async def test_batch_processing_performance(self, mock_tor_manager):
        """Test batch processing performance."""
        pipeline = ClassificationPipeline()
        
        # Generate many test sites
        generator = TestDataGenerator()
        test_sites = []
        
        for i in range(100):
            site_type = i % 4
            if site_type == 0:
                content = generator.generate_forum_page(f"Forum {i}")
            elif site_type == 1:
                content = generator.generate_market_page(f"Market {i}")
            elif site_type == 2:
                content = generator.generate_library_page()
            else:
                content = generator.generate_scam_page()
            
            test_sites.append((
                f"http://test{i}.onion",
                content,
                'text/html',
                None
            ))
        
        # Process in batch
        import time
        start_time = time.time()
        
        results = pipeline.batch_process(test_sites, max_concurrent=10)
        
        end_time = time.time()
        processing_time = end_time - start_time
        
        print(f"Batch processed {len(test_sites)} sites in {processing_time:.2f}s")
        print(f"Average time per site: {processing_time/len(test_sites)*1000:.1f}ms")
        
        # Verify all processed
        assert len(results) == len(test_sites)
        
        # Check performance is reasonable (should be < 1 second per site)
        assert processing_time < len(test_sites) * 0.1  # 100ms per site max
    
    @pytest.mark.asyncio
    async def test_error_handling_and_recovery(self, mock_tor_manager, mock_database):
        """Test error handling in pipeline."""
        config = DiscoveryConfig()
        orchestrator = DiscoveryOrchestrator(mock_tor_manager, mock_database, config)
        
        # Mock various error conditions
        with patch.object(orchestrator.batch_spider, 'crawl_multiple') as mock_crawl:
            # Simulate different error scenarios
            mock_crawl.side_effect = [
                Exception("Network error"),
                Exception("Timeout"),
                {"http://test.onion": {}},  # Empty result
            ]
            
            # Test that orchestrator handles errors gracefully
            results = await orchestrator.discover(
                seed_urls=['http://error1.onion', 'http://error2.onion', 'http://ok.onion']
            )
            
            # Should have errors recorded
            assert results['errors'] > 0
        
        # Test classification pipeline error handling
        pipeline = ClassificationPipeline()
        
        # Test with invalid content
        result = await pipeline.process(
            url='http://invalid.onion',
            content=None,  # Invalid content
            content_type_hint='text/html',
        )
        
        assert not result.is_safe
        assert len(result.errors) > 0
    
    @pytest.mark.asyncio
    async def test_safety_filter_edge_cases(self):
        """Test safety filter with edge cases."""
        from src.classification.safety import SafeContentProcessor, IllegalContentDetector
        
        processor = SafeContentProcessor()
        
        # Test very large content
        large_content = "A" * (processor.max_text_size + 1)
        result, _ = processor.process_content(large_content, 'text/plain')
        assert result.action.value == 'block'
        assert 'size_exceeded' in result.flagged_categories
        
        # Test empty content
        result, _ = processor.process_content("", 'text/plain')
        assert result.action.value == 'allow'  # Empty content is safe
        
        # Test binary content detection
        binary_data = b'\x89PNG\r\n\x1a\n' + b'\x00' * 100  # PNG header
        result, _ = processor.process_content(binary_data, 'application/octet-stream')
        assert result.content_hash is not None
        
        # Test mixed content (HTML with scripts)
        mixed_html = '''
        <html>
        <script>alert("XSS")</script>
        <body>Normal content</body>
        </html>
        '''
        result, _ = processor.process_content(mixed_html, 'text/html')
        assert result.is_safe  # Scripts should be filtered but content is safe


@pytest.mark.performance
class TestPerformanceBenchmarks:
    """Performance benchmark tests."""
    
    @pytest.mark.asyncio
    async def test_harvester_performance(self):
        """Benchmark URL harvester performance."""
        import time
        
        harvester = OnionHarvester()
        
        # Generate large HTML with many links
        html_parts = []
        for i in range(1000):
            html_parts.append(f'<a href="http://link{i:03d}.onion">Link {i}</a>')
        
        html = '<html><body>' + ''.join(html_parts) + '</body></html>'
        
        # Benchmark
        start_time = time.perf_counter()
        
        for _ in range(100):  # Run 100 times
            urls = harvester.extract_from_html(html)
        
        end_time = time.perf_counter()
        
        time_per_extraction = (end_time - start_time) / 100
        print(f"Harvester performance: {time_per_extraction*1000:.2f}ms per extraction")
        
        assert time_per_extraction < 0.01  # Should be < 10ms
    
    @pytest.mark.asyncio
    async def test_classifier_performance(self):
        """Benchmark classifier performance."""
        import time
        
        from src.classification.classifier import RuleBasedClassifier
        
        classifier = RuleBasedClassifier()
        generator = TestDataGenerator()
        
        # Generate test pages
        test_pages = []
        for i in range(100):
            if i % 4 == 0:
                test_pages.append(generator.generate_forum_page())
            elif i % 4 == 1:
                test_pages.append(generator.generate_market_page())
            elif i % 4 == 2:
                test_pages.append(generator.generate_library_page())
            else:
                test_pages.append(generator.generate_scam_page())
        
        # Benchmark
        start_time = time.perf_counter()
        
        for page in test_pages:
            result = classifier.classify(page)
        
        end_time = time.perf_counter()
        
        total_time = end_time - start_time
        time_per_classification = total_time / len(test_pages)
        
        print(f"Classifier performance: {time_per_classification*1000:.2f}ms per page")
        print(f"Total time for {len(test_pages)} pages: {total_time:.2f}s")
        
        assert time_per_classification < 0.1  # Should be < 100ms per page
    
    def test_memory_usage(self):
        """Test memory usage of critical components."""
        import psutil
        import os
        import gc
        
        process = psutil.Process(os.getpid())
        
        # Test harvester memory
        initial_memory = process.memory_info().rss
        
        harvesters = []
        for i in range(100):
            harvester = OnionHarvester()
            harvesters.append(harvester)
        
        after_memory = process.memory_info().rss
        memory_increase = after_memory - initial_memory
        
        print(f"Memory for 100 harvesters: {memory_increase/1024/1024:.2f}MB")
        print(f"Memory per harvester: {memory_increase/100/1024:.2f}KB")
        
        # Clean up
        del harvesters
        gc.collect()
        
        # Should be reasonable memory usage
        assert memory_increase < 100 * 1024 * 1024  # < 100MB for 100 harvesters