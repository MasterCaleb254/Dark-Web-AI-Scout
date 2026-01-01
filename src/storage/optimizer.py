"""
Database optimization and performance tuning.
"""

import asyncio
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
from sqlalchemy import text, Index, func
from sqlalchemy.ext.asyncio import AsyncSession

from src.utils.logger import get_logger

logger = get_logger(__name__)


class DatabaseOptimizer:
    """Optimizes database performance."""
    
    def __init__(self, database):
        """Initialize optimizer.
        
        Args:
            database: Database instance
        """
        self.database = database
    
    async def analyze_performance(self) -> Dict[str, Any]:
        """Analyze database performance.
        
        Returns:
            Performance metrics
        """
        metrics = {}
        
        async with self.database.get_session() as session:
            # Get table sizes
            tables = ['sites', 'discovery_results', 'classifications', 'safety_checks', 'crawl_jobs']
            
            for table in tables:
                try:
                    result = await session.execute(
                        text(f"SELECT COUNT(*) FROM {table}")
                    )
                    count = result.scalar()
                    
                    result = await session.execute(
                        text(f"SELECT pg_total_relation_size('{table}')")
                    )
                    size_bytes = result.scalar() or 0
                    
                    metrics[f'{table}_count'] = count
                    metrics[f'{table}_size_mb'] = size_bytes / 1024 / 1024
                except Exception as e:
                    logger.warning(f"Error analyzing table {table}: {e}")
            
            # Get index usage statistics
            result = await session.execute(text("""
                SELECT schemaname, tablename, indexname, idx_scan, idx_tup_read, idx_tup_fetch
                FROM pg_stat_user_indexes
                ORDER BY idx_scan DESC
                LIMIT 10
            """))
            metrics['index_usage'] = [dict(row._mapping) for row in result.fetchall()]
            
            # Get slow queries
            result = await session.execute(text("""
                SELECT query, calls, total_time, mean_time, rows
                FROM pg_stat_statements
                ORDER BY mean_time DESC
                LIMIT 10
            """))
            metrics['slow_queries'] = [dict(row._mapping) for row in result.fetchall()]
        
        return metrics
    
    async def create_indexes(self) -> List[str]:
        """Create performance indexes.
        
        Returns:
            List of created indexes
        """
        indexes = [
            # Sites table indexes
            "CREATE INDEX IF NOT EXISTS idx_sites_status ON sites(status)",
            "CREATE INDEX IF NOT EXISTS idx_sites_category ON sites(category)",
            "CREATE INDEX IF NOT EXISTS idx_sites_risk ON sites(risk_level, risk_score)",
            "CREATE INDEX IF NOT EXISTS idx_sites_last_checked ON sites(last_checked)",
            "CREATE INDEX IF NOT EXISTS idx_sites_onion_trgm ON sites USING gin(onion_address gin_trgm_ops)",
            
            # Discovery results indexes
            "CREATE INDEX IF NOT EXISTS idx_discovery_site ON discovery_results(site_id)",
            "CREATE INDEX IF NOT EXISTS idx_discovery_method ON discovery_results(discovery_method)",
            "CREATE INDEX IF NOT EXISTS idx_discovery_date ON discovery_results(discovered_at)",
            
            # Classification indexes
            "CREATE INDEX IF NOT EXISTS idx_classification_site ON classifications(site_id)",
            "CREATE INDEX IF NOT EXISTS idx_classification_category ON classifications(category)",
            "CREATE INDEX IF NOT EXISTS idx_classification_date ON classifications(classified_at)",
            
            # Safety checks indexes
            "CREATE INDEX IF NOT EXISTS idx_safety_site ON safety_checks(site_id)",
            "CREATE INDEX IF NOT EXISTS idx_safety_action ON safety_checks(action_taken)",
            "CREATE INDEX IF NOT EXISTS idx_safety_date ON safety_checks(checked_at)",
            
            # Crawl jobs indexes
            "CREATE INDEX IF NOT EXISTS idx_crawl_status ON crawl_jobs(status)",
            "CREATE INDEX IF NOT EXISTS idx_crawl_priority ON crawl_jobs(priority, created_at)",
            "CREATE INDEX IF NOT EXISTS idx_crawl_scheduled ON crawl_jobs(scheduled_for)",
        ]
        
        created = []
        async with self.database.get_session() as session:
            for index_sql in indexes:
                try:
                    await session.execute(text(index_sql))
                    index_name = index_sql.split(' ')[2]  # Extract index name
                    created.append(index_name)
                    logger.info(f"Created index: {index_name}")
                except Exception as e:
                    logger.error(f"Failed to create index: {e}")
            
            await session.commit()
        
        return created
    
    async def vacuum_and_analyze(self, full: bool = False) -> Dict[str, Any]:
        """Run VACUUM and ANALYZE for maintenance.
        
        Args:
            full: Whether to run VACUUM FULL
            
        Returns:
            Maintenance results
        """
        results = {}
        
        async with self.database.get_session() as session:
            # Get database size before
            result = await session.execute(
                text("SELECT pg_database_size(current_database())")
            )
            size_before = result.scalar()
            results['size_before_mb'] = size_before / 1024 / 1024
            
            # Run ANALYZE
            start = datetime.now()
            await session.execute(text("ANALYZE"))
            analyze_time = (datetime.now() - start).total_seconds()
            results['analyze_time_seconds'] = analyze_time
            
            # Run VACUUM
            if full:
                start = datetime.now()
                await session.execute(text("VACUUM FULL"))
                vacuum_time = (datetime.now() - start).total_seconds()
                results['vacuum_full_time_seconds'] = vacuum_time
            else:
                start = datetime.now()
                await session.execute(text("VACUUM"))
                vacuum_time = (datetime.now() - start).total_seconds()
                results['vacuum_time_seconds'] = vacuum_time
            
            # Get database size after
            result = await session.execute(
                text("SELECT pg_database_size(current_database())")
            )
            size_after = result.scalar()
            results['size_after_mb'] = size_after / 1024 / 1024
            results['size_change_mb'] = (size_after - size_before) / 1024 / 1024
            
            await session.commit()
        
        logger.info(f"Maintenance completed: {results}")
        return results
    
    async def partition_tables(self, partition_size: int = 1000000) -> List[str]:
        """Partition large tables for better performance.
        
        Args:
            partition_size: Rows per partition
            
        Returns:
            List of partitioned tables
        """
        partitioned = []
        
        async with self.database.get_session() as session:
            # Check if partitioning extension is available
            result = await session.execute(
                text("SELECT EXISTS(SELECT 1 FROM pg_extension WHERE extname = 'pg_partman')")
            )
            has_partman = result.scalar()
            
            if not has_partman:
                logger.warning("pg_partman extension not installed. Skipping partitioning.")
                return partitioned
            
            # Partition sites table by hash of onion_address
            try:
                await session.execute(text(f"""
                    SELECT partman.create_parent(
                        p_parent_table := 'public.sites',
                        p_control := 'onion_address',
                        p_type := 'hash',
                        p_interval := '{partition_size}',
                        p_premake := 3
                    )
                """))
                partitioned.append('sites')
                logger.info("Partitioned sites table")
            except Exception as e:
                logger.error(f"Failed to partition sites: {e}")
            
            # Partition discovery_results by date
            try:
                await session.execute(text(f"""
                    SELECT partman.create_parent(
                        p_parent_table := 'public.discovery_results',
                        p_control := 'discovered_at',
                        p_type := 'range',
                        p_interval := '1 month',
                        p_premake := 3
                    )
                """))
                partitioned.append('discovery_results')
                logger.info("Partitioned discovery_results table")
            except Exception as e:
                logger.error(f"Failed to partition discovery_results: {e}")
            
            await session.commit()
        
        return partitioned
    
    async def optimize_queries(self) -> Dict[str, Any]:
        """Optimize slow queries."""
        optimizations = {}
        
        async with self.database.get_session() as session:
            # Create materialized views for common queries
            try:
                # View for sites needing classification
                await session.execute(text("""
                    CREATE MATERIALIZED VIEW IF NOT EXISTS sites_needing_classification AS
                    SELECT s.*
                    FROM sites s
                    LEFT JOIN classifications c ON s.id = c.site_id
                    WHERE c.id IS NULL
                    AND s.is_honeypot = FALSE
                    AND s.is_illegal = FALSE
                    AND s.status IN ('discovered', 'active')
                    ORDER BY s.last_checked ASC NULLS FIRST
                """))
                
                # Create index on materialized view
                await session.execute(text(
                    "CREATE INDEX IF NOT EXISTS idx_mv_sites_needing ON sites_needing_classification(last_checked)"
                ))
                
                optimizations['materialized_view_sites_needing'] = 'created'
                
            except Exception as e:
                optimizations['materialized_view_sites_needing'] = f'error: {e}'
            
            # Create summary tables
            try:
                await session.execute(text("""
                    CREATE TABLE IF NOT EXISTS daily_summary (
                        date DATE PRIMARY KEY,
                        sites_discovered INT,
                        sites_classified INT,
                        high_risk_sites INT,
                        avg_processing_time FLOAT
                    )
                """))
                
                optimizations['summary_table'] = 'created'
                
            except Exception as e:
                optimizations['summary_table'] = f'error: {e}'
            
            await session.commit()
        
        return optimizations


class QueryOptimizer:
    """Optimizes database queries."""
    
    @staticmethod
    async def batch_insert(session: AsyncSession, model, data: List[Dict[str, Any]]):
        """Optimized batch insert.
        
        Args:
            session: Database session
            model: SQLAlchemy model
            data: List of dictionaries to insert
        """
        if not data:
            return
        
        # Use COPY for large batches
        if len(data) > 1000:
            await QueryOptimizer._copy_insert(session, model, data)
        else:
            # Use multi-value INSERT for smaller batches
            await session.execute(
                model.__table__.insert(),
                data
            )
    
    @staticmethod
    async def _copy_insert(session: AsyncSession, model, data: List[Dict[str, Any]]):
        """Use COPY command for bulk inserts.
        
        Args:
            session: Database session
            model: SQLAlchemy model
            data: List of dictionaries to insert
        """
        import io
        import csv
        
        # Convert to CSV
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=data[0].keys())
        
        for row in data:
            writer.writerow(row)
        
        output.seek(0)
        
        # Use COPY command
        table_name = model.__table__.name
        columns = ', '.join(data[0].keys())
        
        await session.execute(text(f"""
            COPY {table_name} ({columns}) 
            FROM STDIN 
            WITH (FORMAT CSV, HEADER TRUE)
        """))
        await session.connection().connection.cursor().copy_expert(
            f"COPY {table_name} ({columns}) FROM STDIN WITH CSV HEADER",
            output
        )
    
    @staticmethod
    def paginate_query(query, page: int = 1, page_size: int = 100):
        """Add pagination to query.
        
        Args:
            query: SQLAlchemy query
            page: Page number (1-indexed)
            page_size: Items per page
            
        Returns:
            Paginated query
        """
        offset = (page - 1) * page_size
        return query.offset(offset).limit(page_size)
    
    @staticmethod
    async def get_cached_result(session: AsyncSession, cache_key: str, 
                               ttl: int = 300) -> Optional[Any]:
        """Get cached query result.
        
        Args:
            session: Database session
            cache_key: Cache key
            ttl: Time-to-live in seconds
            
        Returns:
            Cached result or None
        """
        try:
            result = await session.execute(text("""
                SELECT value, expires_at
                FROM query_cache
                WHERE key = :key AND expires_at > NOW()
            """), {'key': cache_key})
            
            row = result.fetchone()
            if row:
                return row[0]
        except Exception:
            # Cache table might not exist
            pass
        
        return None
    
    @staticmethod
    async def set_cached_result(session: AsyncSession, cache_key: str, 
                               value: Any, ttl: int = 300):
        """Set cached query result.
        
        Args:
            session: Database session
            cache_key: Cache key
            value: Value to cache
            ttl: Time-to-live in seconds
        """
        try:
            await session.execute(text("""
                INSERT INTO query_cache (key, value, expires_at)
                VALUES (:key, :value, NOW() + INTERVAL ':ttl seconds')
                ON CONFLICT (key) DO UPDATE SET
                    value = EXCLUDED.value,
                    expires_at = EXCLUDED.expires_at
            """), {'key': cache_key, 'value': value, 'ttl': ttl})
        except Exception as e:
            logger.warning(f"Failed to cache result: {e}")