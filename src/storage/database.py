"""
Database connection and repository pattern implementation.
"""

import asyncio
import contextlib
from typing import AsyncGenerator, Optional, List, Dict, Any
from datetime import datetime, timedelta
from sqlalchemy import select, update, delete, and_, or_, func
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.orm import selectinload
import redis.asyncio as redis

from src.utils.logger import get_logger
from src.utils.config import DatabaseConfig
from .models import Base, Site, DiscoveryResult, Classification, SafetyCheck, CrawlJob, SystemMetrics

logger = get_logger(__name__)


class Database:
    """Database connection and operations."""
    
    def __init__(self, config: DatabaseConfig):
        self.config = config
        
        # PostgreSQL connection
        self.database_url = (
            f"postgresql+asyncpg://{config.postgres_user}:{config.postgres_password}"
            f"@{config.postgres_host}:{config.postgres_port}/{config.postgres_db}"
        )
        
        self.engine = create_async_engine(
            self.database_url,
            echo=False,  # Set to True for SQL debugging
            pool_size=20,
            max_overflow=10,
            pool_pre_ping=True,
        )
        
        self.async_session = async_sessionmaker(
            self.engine,
            class_=AsyncSession,
            expire_on_commit=False,
        )
        
        # Redis connection
        self.redis: Optional[redis.Redis] = None
        
    async def connect(self):
        """Connect to databases."""
        # PostgreSQL
        async with self.engine.begin() as conn:
            # Create tables if they don't exist
            await conn.run_sync(Base.metadata.create_all)
        
        # Redis
        self.redis = redis.Redis(
            host=self.config.redis_host,
            port=self.config.redis_port,
            db=self.config.redis_db,
            decode_responses=True,
        )
        await self.redis.ping()
        
        logger.info("Connected to PostgreSQL and Redis")
    
    async def disconnect(self):
        """Disconnect from databases."""
        if self.redis:
            await self.redis.close()
        await self.engine.dispose()
        logger.info("Disconnected from databases")
    
    @contextlib.asynccontextmanager
    async def get_session(self) -> AsyncGenerator[AsyncSession, None]:
        """Get database session context manager."""
        async with self.async_session() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise
            finally:
                await session.close()


class SiteRepository:
    """Repository for site operations."""
    
    def __init__(self, db: Database):
        self.db = db
    
    async def create_or_update_site(self, session: AsyncSession, onion_address: str, **kwargs) -> Site:
        """Create or update a site."""
        # Check if site exists
        stmt = select(Site).where(Site.onion_address == onion_address)
        result = await session.execute(stmt)
        existing = result.scalar_one_or_none()
        
        if existing:
            # Update existing site
            for key, value in kwargs.items():
                if hasattr(existing, key) and value is not None:
                    setattr(existing, key, value)
            existing.last_checked = datetime.utcnow()
            return existing
        
        # Create new site
        site = Site(onion_address=onion_address, **kwargs)
        session.add(site)
        await session.flush()
        return site
    
    async def get_site(self, session: AsyncSession, site_id: str) -> Optional[Site]:
        """Get site by ID."""
        stmt = select(Site).where(Site.id == site_id)
        result = await session.execute(stmt)
        return result.scalar_one_or_none()
    
    async def get_site_by_address(self, session: AsyncSession, onion_address: str) -> Optional[Site]:
        """Get site by onion address."""
        stmt = select(Site).where(Site.onion_address == onion_address)
        result = await session.execute(stmt)
        return result.scalar_one_or_none()
    
    async def get_pending_sites(self, session: AsyncSession, limit: int = 100) -> List[Site]:
        """Get sites that need to be crawled."""
        stmt = (
            select(Site)
            .where(
                or_(
                    Site.last_checked.is_(None),
                    Site.last_checked < datetime.utcnow() - timedelta(hours=24)
                )
            )
            .where(Site.status.in_(['discovered', 'active']))
            .where(Site.is_honeypot.is_(False))
            .where(Site.is_illegal.is_(False))
            .order_by(Site.last_checked.asc().nullsfirst())
            .limit(limit)
        )
        result = await session.execute(stmt)
        return list(result.scalars().all())
    
    async def search_sites(
        self, 
        session: AsyncSession,
        query: Optional[str] = None,
        category: Optional[str] = None,
        status: Optional[str] = None,
        language: Optional[str] = None,
        limit: int = 100,
        offset: int = 0
    ) -> List[Site]:
        """Search sites with filters."""
        stmt = select(Site)
        
        # Apply filters
        filters = []
        if query:
            filters.append(
                or_(
                    Site.title.ilike(f"%{query}%"),
                    Site.description.ilike(f"%{query}%"),
                    Site.onion_address.ilike(f"%{query}%")
                )
            )
        if category:
            filters.append(Site.category == category)
        if status:
            filters.append(Site.status == status)
        if language:
            filters.append(Site.language == language)
        
        if filters:
            stmt = stmt.where(and_(*filters))
        
        # Apply pagination
        stmt = stmt.order_by(Site.last_checked.desc()).limit(limit).offset(offset)
        
        result = await session.execute(stmt)
        return list(result.scalars().all())


class DiscoveryRepository:
    """Repository for discovery operations."""
    
    def __init__(self, db: Database):
        self.db = db
    
    async def create_discovery_result(
        self, 
        session: AsyncSession,
        site_id: str,
        discovery_method: str,
        source_url: Optional[str] = None,
        confidence: float = 0.0,
        raw_content_hash: Optional[str] = None
    ) -> DiscoveryResult:
        """Create a discovery result."""
        result = DiscoveryResult(
            site_id=site_id,
            source_url=source_url,
            discovery_method=discovery_method,
            confidence=confidence,
            raw_content_hash=raw_content_hash,
        )
        session.add(result)
        await session.flush()
        return result


class CrawlJobRepository:
    """Repository for crawl job operations."""
    
    def __init__(self, db: Database):
        self.db = db
    
    async def create_crawl_job(
        self,
        session: AsyncSession,
        site_id: str,
        url: str,
        priority: int = 0,
        max_depth: int = 1,
        metadata: Optional[Dict[str, Any]] = None
    ) -> CrawlJob:
        """Create a crawl job."""
        job = CrawlJob(
            site_id=site_id,
            url=url,
            priority=priority,
            max_depth=max_depth,
            metadata=metadata or {},
            scheduled_for=datetime.utcnow(),
        )
        session.add(job)
        await session.flush()
        return job
    
    async def get_pending_jobs(self, session: AsyncSession, limit: int = 10) -> List[CrawlJob]:
        """Get pending crawl jobs."""
        stmt = (
            select(CrawlJob)
            .where(CrawlJob.status == 'pending')
            .where(CrawlJob.scheduled_for <= datetime.utcnow())
            .order_by(CrawlJob.priority.desc(), CrawlJob.created_at.asc())
            .limit(limit)
        )
        result = await session.execute(stmt)
        return list(result.scalars().all())
    
    async def update_job_status(
        self,
        session: AsyncSession,
        job_id: str,
        status: str,
        error_message: Optional[str] = None,
        discovered_links: Optional[int] = None
    ) -> None:
        """Update crawl job status."""
        update_data = {"status": status}
        
        if status == 'running':
            update_data["started_at"] = datetime.utcnow()
        elif status in ['completed', 'failed']:
            update_data["completed_at"] = datetime.utcnow()
            if error_message:
                update_data["error_message"] = error_message
            if discovered_links is not None:
                update_data["discovered_links"] = discovered_links
        
        stmt = update(CrawlJob).where(CrawlJob.id == job_id).values(**update_data)
        await session.execute(stmt)


class RedisQueue:
    """Redis-based queue for job management."""
    
    def __init__(self, redis_client: redis.Redis, queue_name: str = "crawl_queue"):
        self.redis = redis_client
        self.queue_name = queue_name
    
    async def push_job(self, job_data: Dict[str, Any], priority: int = 0) -> str:
        """Push a job to the queue with priority."""
        job_id = str(uuid.uuid4())
        job_data["id"] = job_id
        job_data["priority"] = priority
        job_data["timestamp"] = datetime.utcnow().isoformat()
        
        # Use sorted set for priority queue
        await self.redis.zadd(
            self.queue_name,
            {job_id: priority}
        )
        
        # Store job data
        await self.redis.hset(
            f"job:{job_id}",
            mapping=job_data
        )
        
        return job_id
    
    async def pop_job(self) -> Optional[Dict[str, Any]]:
        """Pop highest priority job from queue."""
        # Get highest priority job (lowest score = highest priority)
        job_ids = await self.redis.zrange(self.queue_name, 0, 0)
        
        if not job_ids:
            return None
        
        job_id = job_ids[0]
        
        # Get job data
        job_data = await self.redis.hgetall(f"job:{job_id}")
        
        # Remove from queue
        await self.redis.zrem(self.queue_name, job_id)
        await self.redis.delete(f"job:{job_id}")
        
        return job_data
    
    async def get_queue_length(self) -> int:
        """Get number of jobs in queue."""
        return await self.redis.zcard(self.queue_name)


# Database factory function
async def create_database(config: DatabaseConfig) -> Database:
    """Create and initialize database."""
    db = Database(config)
    await db.connect()
    return db
