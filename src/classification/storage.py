"""
Storage integration for classification results.
"""

import asyncio
from typing import Dict, List, Optional, Any
from datetime import datetime
from uuid import UUID

from src.storage.database import Database
from src.storage.models import Site, Classification, SafetyCheck
from src.classification.pipeline import PipelineResult
from src.utils.logger import get_logger

logger = get_logger(__name__)


class ClassificationStorage:
    """Handles storage of classification results."""
    
    def __init__(self, database: Database):
        """Initialize classification storage.
        
        Args:
            database: Database instance
        """
        self.database = database
    
    async def store_pipeline_result(
        self,
        site_id: UUID,
        pipeline_result: PipelineResult,
        researcher_id: Optional[UUID] = None,
    ) -> Dict[str, Any]:
        """Store pipeline results in database.
        
        Args:
            site_id: Site ID
            pipeline_result: Pipeline processing result
            researcher_id: Optional researcher ID
            
        Returns:
            Dictionary with stored IDs
        """
        stored_ids = {}
        
        async with self.database.get_session() as session:
            try:
                # 1. Update site with classification
                site = await session.get(Site, site_id)
                if site:
                    # Update site status based on classification
                    if pipeline_result.classification_result:
                        site.category = pipeline_result.classification_result.category.value
                        site.subcategory = pipeline_result.classification_result.subcategory
                        site.risk_score = pipeline_result.classification_result.confidence
                    
                    # Update risk level
                    if pipeline_result.risk_score:
                        site.risk_level = pipeline_result.risk_score.level.value
                    
                    # Update flags
                    site.requires_review = pipeline_result.requires_review
                    site.is_honeypot = (
                        pipeline_result.classification_result and
                        pipeline_result.classification_result.category.value == 'honeypot'
                    )
                    
                    site.last_checked = datetime.now()
                
                # 2. Store safety check result
                safety_check = SafetyCheck(
                    site_id=site_id,
                    is_safe=pipeline_result.is_safe,
                    action_taken=pipeline_result.safety_result.action.value,
                    flagged_categories=pipeline_result.safety_result.flagged_categories,
                    risk_factors=pipeline_result.safety_result.risk_factors,
                    filter_version="1.0",
                    checked_content_hash=pipeline_result.safety_result.content_hash,
                    checked_at=datetime.now(),
                )
                session.add(safety_check)
                await session.flush()
                stored_ids['safety_check_id'] = safety_check.id
                
                # 3. Store classification result
                if pipeline_result.classification_result:
                    classification = Classification(
                        site_id=site_id,
                        category=pipeline_result.classification_result.category.value,
                        subcategory=pipeline_result.classification_result.subcategory,
                        confidence=pipeline_result.classification_result.confidence,
                        model_version=pipeline_result.classification_result.model_version,
                        model_type='rule_based',
                        features=pipeline_result.classification_result.features,
                        classified_at=pipeline_result.classification_result.processed_at,
                    )
                    session.add(classification)
                    await session.flush()
                    stored_ids['classification_id'] = classification.id
                
                await session.commit()
                
                logger.info(f"Stored classification results for site {site_id}")
                
            except Exception as e:
                await session.rollback()
                logger.error(f"Failed to store classification results: {e}")
                raise
        
        return stored_ids
    
    async def get_classification_history(
        self,
        site_id: UUID,
        limit: int = 10,
    ) -> List[Dict[str, Any]]:
        """Get classification history for a site.
        
        Args:
            site_id: Site ID
            limit: Maximum number of results
            
        Returns:
            List of classification records
        """
        async with self.database.get_session() as session:
            stmt = (
                "SELECT * FROM classifications "
                "WHERE site_id = :site_id "
                "ORDER BY classified_at DESC "
                "LIMIT :limit"
            )
            
            result = await session.execute(
                stmt,
                {'site_id': site_id, 'limit': limit}
            )
            
            rows = result.fetchall()
            
            # Convert to dictionaries
            classifications = []
            for row in rows:
                classifications.append(dict(row._mapping))
            
            return classifications
    
    async def get_sites_needing_classification(
        self,
        limit: int = 100,
        min_age_hours: int = 1,
    ) -> List[Dict[str, Any]]:
        """Get sites that need classification.
        
        Args:
            limit: Maximum number of sites
            min_age_hours: Minimum hours since last check
            
        Returns:
            List of site records
        """
        async with self.database.get_session() as session:
            stmt = """
                SELECT s.* FROM sites s
                LEFT JOIN classifications c ON s.id = c.site_id
                WHERE (c.id IS NULL OR s.last_checked < NOW() - INTERVAL ':min_age_hours hours')
                AND s.is_honeypot = FALSE
                AND s.is_illegal = FALSE
                AND s.status IN ('discovered', 'active')
                ORDER BY s.last_checked ASC NULLS FIRST
                LIMIT :limit
            """
            
            result = await session.execute(
                stmt,
                {'limit': limit, 'min_age_hours': min_age_hours}
            )
            
            rows = result.fetchall()
            
            # Convert to dictionaries
            sites = []
            for row in rows:
                sites.append(dict(row._mapping))
            
            return sites
    
    async def get_high_risk_sites(
        self,
        risk_level: str = 'high',
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        """Get high-risk sites.
        
        Args:
            risk_level: Risk level to filter by
            limit: Maximum number of sites
            
        Returns:
            List of high-risk site records
        """
        async with self.database.get_session() as session:
            stmt = """
                SELECT s.* FROM sites s
                WHERE s.risk_level = :risk_level
                OR (s.requires_review = TRUE AND s.is_honeypot = FALSE)
                ORDER BY s.risk_score DESC
                LIMIT :limit
            """
            
            result = await session.execute(
                stmt,
                {'risk_level': risk_level, 'limit': limit}
            )
            
            rows = result.fetchall()
            
            # Convert to dictionaries
            sites = []
            for row in rows:
                sites.append(dict(row._mapping))
            
            return sites
    
    async def update_site_risk(
        self,
        site_id: UUID,
        risk_level: str,
        risk_score: float,
        requires_review: bool,
    ) -> bool:
        """Update site risk information.
        
        Args:
            site_id: Site ID
            risk_level: New risk level
            risk_score: New risk score
            requires_review: Whether review is required
            
        Returns:
            True if successful
        """
        async with self.database.get_session() as session:
            try:
                site = await session.get(Site, site_id)
                if site:
                    site.risk_level = risk_level
                    site.risk_score = risk_score
                    site.requires_review = requires_review
                    site.last_checked = datetime.now()
                    
                    await session.commit()
                    return True
                
                return False
                
            except Exception as e:
                await session.rollback()
                logger.error(f"Failed to update site risk: {e}")
                return False