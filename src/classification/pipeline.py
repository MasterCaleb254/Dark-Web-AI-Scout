"""
Classification pipeline - orchestrates safety checking, classification, and risk scoring.
"""

import asyncio
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from datetime import datetime
import json

from src.classification.safety import (
    SafeContentProcessor, IllegalContentDetector, 
    SafetyResult, SafetyAction, ContentType
)
from src.classification.classifier import (
    RuleBasedClassifier, ClassificationResult, SiteCategory
)
from src.classification.risk import (
    RiskScorer, RiskScore, RiskLevel, ReputationTracker
)
from src.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class PipelineResult:
    """Complete pipeline processing result."""
    # Input
    url: str
    content: str
    content_type: ContentType
    
    # Safety results
    safety_result: SafetyResult
    sanitized_content: Optional[str] = None
    
    # Classification results
    classification_result: Optional[ClassificationResult] = None
    
    # Risk assessment
    risk_score: Optional[RiskScore] = None
    
    # Metadata
    metadata: Dict[str, Any] = None
    processing_time: float = 0.0
    errors: List[str] = None
    
    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}
        if self.errors is None:
            self.errors = []
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for storage."""
        return {
            'url': self.url,
            'content_type': self.content_type.value,
            'safety': {
                'action': self.safety_result.action.value,
                'confidence': self.safety_result.confidence,
                'flagged_categories': self.safety_result.flagged_categories,
                'content_hash': self.safety_result.content_hash,
            },
            'classification': self.classification_result.to_dict() if self.classification_result else None,
            'risk': self.risk_score.to_dict() if self.risk_score else None,
            'metadata': self.metadata,
            'processing_time': self.processing_time,
            'errors': self.errors,
        }
    
    @property
    def is_safe(self) -> bool:
        """Check if content is safe."""
        return self.safety_result.is_safe
    
    @property
    def requires_review(self) -> bool:
        """Check if human review is required."""
        if not self.is_safe:
            return False
        
        if self.safety_result.action == SafetyAction.REVIEW:
            return True
        
        if self.risk_score and self.risk_score.is_high:
            return True
        
        if self.classification_result and self.classification_result.category in [
            SiteCategory.SCAM, SiteCategory.HONEYPOT
        ]:
            return True
        
        return False


class ClassificationPipeline:
    """Orchestrates the complete classification pipeline."""
    
    def __init__(
        self,
        safety_processor: Optional[SafeContentProcessor] = None,
        classifier: Optional[RuleBasedClassifier] = None,
        risk_scorer: Optional[RiskScorer] = None,
        reputation_tracker: Optional[ReputationTracker] = None,
        enable_safety: bool = True,
        enable_classification: bool = True,
        enable_risk_scoring: bool = True,
    ):
        """Initialize classification pipeline.
        
        Args:
            safety_processor: Safety content processor
            classifier: Site classifier
            risk_scorer: Risk scorer
            reputation_tracker: Reputation tracker
            enable_safety: Whether to enable safety checking
            enable_classification: Whether to enable classification
            enable_risk_scoring: Whether to enable risk scoring
        """
        self.safety_processor = safety_processor or SafeContentProcessor()
        self.classifier = classifier or RuleBasedClassifier()
        self.risk_scorer = risk_scorer or RiskScorer()
        self.reputation_tracker = reputation_tracker or ReputationTracker()
        
        self.enable_safety = enable_safety
        self.enable_classification = enable_classification
        self.enable_risk_scoring = enable_risk_scoring
        
        # Statistics
        self.stats = {
            'processed': 0,
            'blocked': 0,
            'classified': 0,
            'risks_assessed': 0,
            'avg_processing_time': 0.0,
            'errors': 0,
        }
    
    async def process(
        self,
        url: str,
        content: Any,
        content_type_hint: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> PipelineResult:
        """Process content through the pipeline.
        
        Args:
            url: Source URL
            content: Content to process
            content_type_hint: Optional content type hint
            metadata: Additional metadata
            
        Returns:
            PipelineResult with all processing results
        """
        start_time = asyncio.get_event_loop().time()
        self.stats['processed'] += 1
        
        result = PipelineResult(
            url=url,
            content=str(content)[:1000] if content else "",  # Store snippet
            content_type=ContentType.UNKNOWN,
            metadata=metadata or {},
        )
        
        try:
            # Step 1: Safety Check
            if self.enable_safety:
                safety_result, safe_content = self.safety_processor.process_content(
                    content, content_type_hint, url
                )
                result.safety_result = safety_result
                result.content_type = safety_result.content_hash and ContentType.TEXT or ContentType.UNKNOWN
                
                if not safety_result.is_safe:
                    result.errors.append(f"Safety check failed: {safety_result.action.value}")
                    self.stats['blocked'] += 1
                    
                    # If blocked, we can't proceed further
                    processing_time = asyncio.get_event_loop().time() - start_time
                    result.processing_time = processing_time
                    self._update_avg_time(processing_time)
                    return result
                
                # Store sanitized content if available
                if safe_content and isinstance(safe_content, bytes):
                    try:
                        result.sanitized_content = safe_content.decode('utf-8', errors='ignore')
                    except Exception:
                        result.sanitized_content = str(safe_content)[:10000]
                elif safe_content:
                    result.sanitized_content = str(safe_content)[:10000]
            
            # Step 2: Classification
            if self.enable_classification and result.sanitized_content:
                try:
                    classification_result = self.classifier.classify(
                        result.sanitized_content,
                        url=url,
                        metadata=metadata,
                    )
                    result.classification_result = classification_result
                    self.stats['classified'] += 1
                except Exception as e:
                    result.errors.append(f"Classification failed: {str(e)}")
                    logger.error(f"Classification error for {url}: {e}")
            
            # Step 3: Risk Assessment
            if self.enable_risk_scoring:
                try:
                    risk_score = self.risk_scorer.assess_risk(
                        content=result.sanitized_content or str(content)[:10000],
                        url=url,
                        metadata=metadata,
                        classification=result.classification_result.to_dict() if result.classification_result else None,
                        safety_result=result.safety_result.__dict__ if result.safety_result else None,
                    )
                    result.risk_score = risk_score
                    self.stats['risks_assessed'] += 1
                    
                    # Update reputation
                    if result.classification_result:
                        reputation = self.reputation_tracker.update_reputation(
                            onion_address=url,
                            risk_score=risk_score,
                            classification=result.classification_result.to_dict(),
                            uptime=metadata.get('uptime') if metadata else None,
                        )
                        result.metadata['reputation'] = reputation
                        
                except Exception as e:
                    result.errors.append(f"Risk assessment failed: {str(e)}")
                    logger.error(f"Risk assessment error for {url}: {e}")
            
        except Exception as e:
            result.errors.append(f"Pipeline processing failed: {str(e)}")
            self.stats['errors'] += 1
            logger.error(f"Pipeline error for {url}: {e}")
        
        finally:
            processing_time = asyncio.get_event_loop().time() - start_time
            result.processing_time = processing_time
            self._update_avg_time(processing_time)
        
        return result
    
    def _update_avg_time(self, new_time: float):
        """Update average processing time.
        
        Args:
            new_time: New processing time
        """
        current_avg = self.stats['avg_processing_time']
        count = self.stats['processed']
        
        # Exponential moving average
        alpha = 0.1
        if count == 1:
            self.stats['avg_processing_time'] = new_time
        else:
            self.stats['avg_processing_time'] = (1 - alpha) * current_avg + alpha * new_time
    
    def batch_process(
        self,
        items: List[Tuple[str, Any, Optional[str], Optional[Dict[str, Any]]]],
        max_concurrent: int = 5,
    ) -> List[PipelineResult]:
        """Process multiple items in batch.
        
        Args:
            items: List of (url, content, content_type_hint, metadata) tuples
            max_concurrent: Maximum concurrent processing tasks
            
        Returns:
            List of PipelineResults
        """
        async def process_batch():
            semaphore = asyncio.Semaphore(max_concurrent)
            
            async def process_with_semaphore(item):
                async with semaphore:
                    return await self.process(*item)
            
            tasks = [process_with_semaphore(item) for item in items]
            return await asyncio.gather(*tasks, return_exceptions=True)
        
        # Run batch processing
        results = asyncio.run(process_batch())
        
        # Filter out exceptions
        processed_results = []
        for result in results:
            if isinstance(result, Exception):
                logger.error(f"Batch processing error: {result}")
                self.stats['errors'] += 1
            else:
                processed_results.append(result)
        
        return processed_results
    
    def get_safety_stats(self) -> Dict[str, Any]:
        """Get safety processor statistics.
        
        Returns:
            Dictionary with safety statistics
        """
        if hasattr(self.safety_processor.detector, 'get_stats'):
            return self.safety_processor.detector.get_stats()
        return {}
    
    def get_classification_stats(self) -> Dict[str, Any]:
        """Get classifier statistics.
        
        Returns:
            Dictionary with classification statistics
        """
        if self.classifier:
            return self.classifier.get_stats()
        return {}
    
    def get_risk_stats(self) -> Dict[str, Any]:
        """Get risk scorer statistics.
        
        Returns:
            Dictionary with risk statistics
        """
        if self.risk_scorer:
            return self.risk_scorer.get_stats()
        return {}
    
    def get_pipeline_stats(self) -> Dict[str, Any]:
        """Get complete pipeline statistics.
        
        Returns:
            Dictionary with all statistics
        """
        stats = self.stats.copy()
        stats.update({
            'safety': self.get_safety_stats(),
            'classification': self.get_classification_stats(),
            'risk': self.get_risk_stats(),
        })
        return stats