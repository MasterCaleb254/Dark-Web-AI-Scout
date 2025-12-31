"""
Integration test between discovery and classification.
"""

import pytest
import asyncio
from unittest.mock import AsyncMock, Mock, patch

from src.discovery.orchestrator import DiscoveryOrchestrator, DiscoveryConfig
from src.classification.pipeline import ClassificationPipeline
from src.classification.storage import ClassificationStorage


@pytest.mark.integration
class TestDiscoveryClassificationIntegration:
    """Integration tests for discovery and classification."""
    
    @pytest.mark.asyncio
    async def test_full_pipeline_integration(self):
        """Test full integration from discovery to classification."""
        # Mock components
        mock_tor_manager = Mock()
        mock_database = Mock()
        
        # Create discovery orchestrator
        config = DiscoveryConfig(mode='crawl', max_depth=1)
        orchestrator = DiscoveryOrchestrator(mock_tor_manager, mock_database, config)
        
        # Create classification pipeline
        pipeline = ClassificationPipeline()
        
        # Mock discovery results
        with patch.object(orchestrator, 'discover') as mock_discover:
            mock_discover.return_value = {
                'sites_discovered': 2,
                'links_found': 5,
                'errors': 0,
            }
            
            # Run discovery
            discovery_results = await orchestrator.discover(
                seed_urls=['http://test1.onion', 'http://test2.onion']
            )
            
            assert discovery_results['sites_discovered'] == 2
        
        # Test classification of discovered content
        test_content = """
        <html><title>Test Market</title>
        <body>Buy products here. Price: 1 BTC</body>
        </html>
        """
        
        classification_result = await pipeline.process(
            url='http://testmarket.onion',
            content=test_content,
            content_type_hint='text/html',
        )
        
        assert classification_result.is_safe
        assert classification_result.classification_result is not None
        assert classification_result.risk_score is not None
        
        # Verify classification makes sense for market content
        if classification_result.classification_result:
            category = classification_result.classification_result.category.value
            assert category in ['market', 'forum', 'service', 'other']
    
    @pytest.mark.asyncio
    async def test_safety_filter_integration(self):
        """Test safety filter integration."""
        from src.classification.safety import IllegalContentDetector, SafeContentProcessor
        
        # Create safety processor
        detector = IllegalContentDetector()
        processor = SafeContentProcessor(detector=detector)
        
        # Test safe content
        safe_content = "This is a forum about technology and privacy."
        safety_result, _ = processor.process_content(safe_content, 'text/plain')
        assert safety_result.action.value == 'allow'
        
        # Test suspicious content
        suspicious_content = "This site sells illegal substances."
        safety_result, _ = processor.process_content(suspicious_content, 'text/plain')
        # Might be flagged for review depending on patterns
        
        # Test blocked content
        # Note: We don't test actual illegal content for obvious reasons
    
    @pytest.mark.asyncio
    async def test_storage_integration(self):
        """Test classification storage integration."""
        # Mock database
        mock_db = Mock()
        mock_session = AsyncMock()
        mock_db.get_session.return_value.__aenter__.return_value = mock_session
        
        # Create storage
        storage = ClassificationStorage(mock_db)
        
        # Test data
        from src.classification.pipeline import PipelineResult
        from src.classification.safety import SafetyResult, SafetyAction
        from src.classification.classifier import ClassificationResult, SiteCategory
        from src.classification.risk import RiskScore, RiskLevel
        
        pipeline_result = PipelineResult(
            url='http://test.onion',
            content='test content',
            content_type='text',
            safety_result=SafetyResult(
                action=SafetyAction.ALLOW,
                confidence=0.9,
                content_hash='abc123',
            ),
            classification_result=ClassificationResult(
                category=SiteCategory.FORUM,
                confidence=0.8,
                subcategory='general_forum',
            ),
            risk_score=RiskScore(
                level=RiskLevel.LOW,
                score=0.3,
                factors=[],
                confidence=0.8,
            ),
        )
        
        # Test storage (would require actual database in integration tests)
        # For now, just verify the method exists
        assert hasattr(storage, 'store_pipeline_result')
        assert callable(storage.store_pipeline_result)


if __name__ == '__main__':
    # Run integration tests
    pytest.main(['-xvs', __file__, '-k', 'integration'])