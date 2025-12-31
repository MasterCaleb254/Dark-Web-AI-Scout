"""
FastAPI application for Arachne API.
"""

from fastapi import FastAPI, HTTPException, Depends, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
import uvicorn

from src.utils.logger import setup_logger, get_logger
from src.utils.config import load_config
from src.storage.database import Database, SiteRepository, ClassificationStorage
from src.orchestrator.scheduler import Scheduler
from src.monitoring.health import HealthMonitor

logger = get_logger(__name__)

# Create FastAPI app
app = FastAPI(
    title="Arachne API",
    description="API for Dark Web Research Platform",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, restrict this
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global dependencies
config = load_config()
db = None
scheduler = None
health_monitor = None


@app.on_event("startup")
async def startup_event():
    """Initialize resources on startup."""
    global db, scheduler, health_monitor
    
    logger.info("Starting Arachne API...")
    
    # Initialize database
    from src.storage.database import create_database
    db = await create_database(config.database)
    
    # Initialize scheduler (would require other components)
    # scheduler = Scheduler(...)
    
    # Initialize health monitor
    # health_monitor = HealthMonitor(...)
    
    logger.info("Arachne API started")


@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup resources on shutdown."""
    logger.info("Shutting down Arachne API...")
    
    if db:
        await db.disconnect()
    
    if scheduler:
        await scheduler.stop()
    
    if health_monitor:
        await health_monitor.stop()
    
    logger.info("Arachne API shutdown complete")


# Dependency to get database session
async def get_db():
    """Get database session."""
    async with db.get_session() as session:
        yield session


@app.get("/")
async def root():
    """Root endpoint."""
    return {
        "name": "Arachne API",
        "version": "1.0.0",
        "status": "operational",
        "timestamp": datetime.now().isoformat(),
    }


@app.get("/health")
async def health():
    """Health check endpoint."""
    if health_monitor:
        return health_monitor.get_health_summary()
    
    return {
        "overall": "healthy",
        "timestamp": datetime.now().isoformat(),
    }


@app.get("/sites")
async def get_sites(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    category: Optional[str] = None,
    status: Optional[str] = None,
    risk_level: Optional[str] = None,
    search: Optional[str] = None,
    db_session = Depends(get_db),
):
    """Get sites with filtering and pagination."""
    repo = SiteRepository(db)
    
    # Calculate offset
    offset = (page - 1) * page_size
    
    # Get sites
    sites = await repo.search_sites(
        session=db_session,
        query=search,
        category=category,
        status=status,
        language=None,  # Add if needed
        limit=page_size,
        offset=offset,
    )
    
    # Convert to dictionaries
    site_dicts = []
    for site in sites:
        site_dict = {
            "id": str(site.id),
            "onion_address": site.onion_address,
            "status": site.status,
            "category": site.category,
            "risk_level": site.risk_level,
            "risk_score": site.risk_score,
            "title": site.title,
            "description": site.description,
            "first_seen": site.first_seen.isoformat() if site.first_seen else None,
            "last_checked": site.last_checked.isoformat() if site.last_checked else None,
            "requires_review": site.requires_review,
            "is_honeypot": site.is_honeypot,
        }
        site_dicts.append(site_dict)
    
    # Get total count
    count_stmt = "SELECT COUNT(*) FROM sites"
    result = await db_session.execute(count_stmt)
    total_count = result.scalar()
    
    return {
        "sites": site_dicts,
        "pagination": {
            "page": page,
            "page_size": page_size,
            "total": total_count,
            "pages": (total_count + page_size - 1) // page_size,
        },
    }


@app.get("/sites/{site_id}")
async def get_site(site_id: str, db_session = Depends(get_db)):
    """Get a specific site by ID."""
    repo = SiteRepository(db)
    
    site = await repo.get_site(db_session, site_id)
    if not site:
        raise HTTPException(status_code=404, detail="Site not found")
    
    # Get classification history
    storage = ClassificationStorage(db)
    classifications = await storage.get_classification_history(site_id, limit=10)
    
    return {
        "site": {
            "id": str(site.id),
            "onion_address": site.onion_address,
            "status": site.status,
            "category": site.category,
            "subcategory": site.subcategory,
            "risk_level": site.risk_level,
            "risk_score": site.risk_score,
            "title": site.title,
            "description": site.description,
            "language": site.language,
            "first_seen": site.first_seen.isoformat() if site.first_seen else None,
            "last_checked": site.last_checked.isoformat() if site.last_checked else None,
            "requires_review": site.requires_review,
            "is_honeypot": site.is_honeypot,
            "is_illegal": site.is_illegal,
            "tags": site.tags,
            "metadata": site.metadata,
        },
        "classifications": classifications,
    }


@app.get("/stats")
async def get_stats(db_session = Depends(get_db)):
    """Get system statistics."""
    # Site statistics
    stmt = """
        SELECT 
            COUNT(*) as total_sites,
            COUNT(CASE WHEN category IS NOT NULL THEN 1 END) as classified_sites,
            COUNT(CASE WHEN requires_review = TRUE THEN 1 END) as sites_needing_review,
            COUNT(CASE WHEN is_honeypot = TRUE THEN 1 END) as honeypots,
            COUNT(CASE WHEN risk_level = 'critical' THEN 1 END) as critical_risk,
            COUNT(CASE WHEN risk_level = 'high' THEN 1 END) as high_risk,
            COUNT(CASE WHEN status = 'active' THEN 1 END) as active_sites
        FROM sites
    """
    result = await db_session.execute(stmt)
    site_stats = dict(result.fetchone()._mapping)
    
    # Category distribution
    stmt = """
        SELECT category, COUNT(*) as count
        FROM sites
        WHERE category IS NOT NULL
        GROUP BY category
        ORDER BY count DESC
    """
    result = await db_session.execute(stmt)
    categories = []
    for row in result.fetchall():
        categories.append({
            "category": row[0],
            "count": row[1],
        })
    
    # Discovery statistics (last 7 days)
    stmt = """
        SELECT 
            DATE(discovered_at) as date,
            COUNT(*) as discoveries
        FROM discovery_results 
        WHERE discovered_at > NOW() - INTERVAL '7 days'
        GROUP BY DATE(discovered_at)
        ORDER BY date
    """
    result = await db_session.execute(stmt)
    discovery_trend = []
    for row in result.fetchall():
        discovery_trend.append({
            "date": row[0].isoformat() if hasattr(row[0], 'isoformat') else str(row[0]),
            "discoveries": row[1],
        })
    
    return {
        "site_statistics": site_stats,
        "categories": categories,
        "discovery_trend": discovery_trend,
        "timestamp": datetime.now().isoformat(),
    }


@app.get("/alerts")
async def get_alerts(limit: int = Query(20, ge=1, le=100)):
    """Get recent alerts."""
    if health_monitor:
        alerts = health_monitor.get_recent_alerts(limit=limit)
    else:
        alerts = []
    
    return {
        "alerts": alerts,
        "count": len(alerts),
    }


@app.post("/sites/{site_id}/classify")
async def classify_site(site_id: str):
    """Trigger classification for a specific site."""
    # This would add a classification task to the scheduler
    if scheduler:
        task = {
            'type': 'classification',
            'priority': 10,  # High priority
            'site_id': site_id,
            'created_at': datetime.now().isoformat(),
            'scheduled_for': datetime.now().isoformat(),
        }
        await scheduler.schedule_task(task)
        
        return {
            "status": "scheduled",
            "site_id": site_id,
            "message": "Classification task scheduled",
        }
    
    raise HTTPException(status_code=503, detail="Scheduler not available")


@app.post("/discover")
async def trigger_discovery():
    """Trigger a discovery run."""
    if scheduler:
        task = {
            'type': 'discovery',
            'priority': 5,  # Medium priority
            'created_at': datetime.now().isoformat(),
            'scheduled_for': datetime.now().isoformat(),
        }
        await scheduler.schedule_task(task)
        
        return {
            "status": "scheduled",
            "message": "Discovery task scheduled",
        }
    
    raise HTTPException(status_code=503, detail="Scheduler not available")


@app.get("/system/stats")
async def get_system_stats():
    """Get system performance statistics."""
    import psutil
    
    cpu_percent = psutil.cpu_percent(interval=1)
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage('/')
    
    return {
        "cpu_percent": cpu_percent,
        "memory_percent": memory.percent,
        "memory_total_gb": memory.total / (1024**3),
        "memory_used_gb": memory.used / (1024**3),
        "disk_percent": disk.percent,
        "disk_total_gb": disk.total / (1024**3),
        "disk_used_gb": disk.used / (1024**3),
        "timestamp": datetime.now().isoformat(),
    }


if __name__ == "__main__":
    # Run the API server
    setup_logger(level="INFO")
    
    uvicorn.run(
        "src.api.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,  # Disable in production
        log_level="info",
    )