"""
REST API for integration with other tools.
"""

import asyncio
import json
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
from fastapi import FastAPI, HTTPException, Depends, Query, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field
import uvicorn

from src.utils.logger import get_logger, setup_logger
from src.utils.config import load_config
from src.storage.database import Database, create_database
from src.classification.pipeline import ClassificationPipeline
from src.integration.plugins import PluginManager, EventData, PluginEvent

logger = get_logger(__name__)

# FastAPI app
app = FastAPI(
    title="Arachne API",
    description="Dark Web Research Platform API",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, restrict this
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security
security = HTTPBearer()

# Global instances
database: Optional[Database] = None
plugin_manager: Optional[PluginManager] = None
classification_pipeline: Optional[ClassificationPipeline] = None


# ==================== Models ====================

class SiteCreate(BaseModel):
    """Model for creating a site."""
    onion_address: str = Field(..., description="Onion address (56 characters)")
    title: Optional[str] = Field(None, description="Site title")
    description: Optional[str] = Field(None, description="Site description")
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict)


class SiteUpdate(BaseModel):
    """Model for updating a site."""
    category: Optional[str] = Field(None, description="Site category")
    risk_level: Optional[str] = Field(None, description="Risk level")
    requires_review: Optional[bool] = Field(None, description="Requires human review")
    tags: Optional[List[str]] = Field(None, description="Tags")
    metadata: Optional[Dict[str, Any]] = Field(None, description="Metadata")


class ClassificationRequest(BaseModel):
    """Model for classification request."""
    content: str = Field(..., description="Content to classify")
    url: Optional[str] = Field(None, description="Source URL")
    content_type: Optional[str] = Field("text/html", description="Content type")


class SearchQuery(BaseModel):
    """Model for search query."""
    query: Optional[str] = Field(None, description="Search query")
    category: Optional[str] = Field(None, description="Category filter")
    risk_level: Optional[str] = Field(None, description="Risk level filter")
    status: Optional[str] = Field(None, description="Status filter")
    limit: int = Field(100, description="Maximum results")
    offset: int = Field(0, description="Result offset")


class StatsQuery(BaseModel):
    """Model for statistics query."""
    timeframe: str = Field("7d", description="Timeframe: 1d, 7d, 30d, all")
    group_by: Optional[str] = Field(None, description="Group by: category, risk_level, status")


# ==================== Dependencies ====================

async def get_db():
    """Get database connection."""
    if database is None:
        raise HTTPException(status_code=500, detail="Database not initialized")
    return database


async def get_plugins():
    """Get plugin manager."""
    if plugin_manager is None:
        raise HTTPException(status_code=500, detail="Plugin manager not initialized")
    return plugin_manager


async def get_pipeline():
    """Get classification pipeline."""
    if classification_pipeline is None:
        raise HTTPException(status_code=500, detail="Classification pipeline not initialized")
    return classification_pipeline


async def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Verify API token.
    
    In production, implement proper authentication.
    """
    token = credentials.credentials
    
    # Simple token validation (replace with proper auth)
    config = load_config()
    valid_tokens = config.get('api_tokens', [])
    
    if token not in valid_tokens:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    return token


# ==================== Startup/Shutdown ====================

@app.on_event("startup")
async def startup_event():
    """Initialize API on startup."""
    global database, plugin_manager, classification_pipeline
    
    try:
        config = load_config()
        
        # Initialize database
        database = await create_database(config.database)
        logger.info("Database initialized")
        
        # Initialize plugin manager
        plugin_config = config.get('plugins', {})
        plugin_manager = PluginLoader.load_from_config(plugin_config)
        await plugin_manager.initialize_all()
        logger.info(f"Plugins initialized: {len(plugin_manager.plugins)}")
        
        # Initialize classification pipeline
        classification_pipeline = ClassificationPipeline()
        logger.info("Classification pipeline initialized")
        
    except Exception as e:
        logger.error(f"Failed to initialize API: {e}")
        raise


@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown."""
    if plugin_manager:
        await plugin_manager.shutdown_all()
        logger.info("Plugins shutdown")
    
    if database:
        await database.disconnect()
        logger.info("Database disconnected")


# ==================== API Endpoints ====================

@app.get("/api/health", tags=["System"])
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "version": "1.0.0",
    }


@app.get("/api/stats", tags=["Statistics"])
async def get_statistics(
    timeframe: str = Query("7d", description="Timeframe: 1d, 7d, 30d, all"),
    db: Database = Depends(get_db),
):
    """Get system statistics."""
    async with db.get_session() as session:
        # Calculate timeframe
        if timeframe == "1d":
            since = datetime.now() - timedelta(days=1)
        elif timeframe == "7d":
            since = datetime.now() - timedelta(days=7)
        elif timeframe == "30d":
            since = datetime.now() - timedelta(days=30)
        else:
            since = None
        
        # Build query
        query = "SELECT COUNT(*) as total_sites FROM sites"
        if since:
            query += f" WHERE first_seen >= '{since.isoformat()}'"
        
        result = await session.execute(query)
        total_sites = result.scalar() or 0
        
        # Get category distribution
        query = """
            SELECT category, COUNT(*) as count
            FROM sites
            WHERE category IS NOT NULL
            GROUP BY category
            ORDER BY count DESC
        """
        
        result = await session.execute(query)
        categories = {row[0]: row[1] for row in result.fetchall()}
        
        # Get risk distribution
        query = """
            SELECT risk_level, COUNT(*) as count
            FROM sites
            WHERE risk_level IS NOT NULL
            GROUP BY risk_level
        """
        
        result = await session.execute(query)
        risks = {row[0]: row[1] for row in result.fetchall()}
        
        return {
            "timeframe": timeframe,
            "total_sites": total_sites,
            "categories": categories,
            "risk_levels": risks,
            "updated_at": datetime.now().isoformat(),
        }


@app.post("/api/sites", tags=["Sites"])
async def create_site(
    site: SiteCreate,
    background_tasks: BackgroundTasks,
    db: Database = Depends(get_db),
    plugins: PluginManager = Depends(get_plugins),
    token: str = Depends(verify_token),
):
    """Create a new site."""
    async with db.get_session() as session:
        # Check if site exists
        from src.storage.models import Site
        
        existing = await session.execute(
            "SELECT * FROM sites WHERE onion_address = :address",
            {'address': site.onion_address}
        )
        
        if existing.fetchone():
            raise HTTPException(status_code=409, detail="Site already exists")
        
        # Create site
        new_site = Site(
            onion_address=site.onion_address,
            title=site.title,
            description=site.description,
            metadata=site.metadata,
            first_seen=datetime.now(),
            status='discovered',
        )
        
        session.add(new_site)
        await session.commit()
        
        # Emit event
        event = EventData(
            event_type=PluginEvent.SITE_DISCOVERED,
            timestamp=datetime.now().timestamp(),
            data={
                'site_id': str(new_site.id),
                'onion_address': new_site.onion_address,
                'title': new_site.title,
                'metadata': new_site.metadata,
            }
        )
        
        background_tasks.add_task(plugins.emit_event, event)
        
        return {
            "id": str(new_site.id),
            "onion_address": new_site.onion_address,
            "status": "created",
        }


@app.get("/api/sites/{site_id}", tags=["Sites"])
async def get_site(
    site_id: str,
    db: Database = Depends(get_db),
    token: str = Depends(verify_token),
):
    """Get site by ID."""
    async with db.get_session() as session:
        from src.storage.models import Site
        
        site = await session.get(Site, site_id)
        if not site:
            raise HTTPException(status_code=404, detail="Site not found")
        
        # Get classification history
        classifications = await session.execute(
            "SELECT * FROM classifications WHERE site_id = :site_id ORDER BY classified_at DESC LIMIT 10",
            {'site_id': site_id}
        )
        
        # Get safety checks
        safety_checks = await session.execute(
            "SELECT * FROM safety_checks WHERE site_id = :site_id ORDER BY checked_at DESC LIMIT 10",
            {'site_id': site_id}
        )
        
        return {
            "id": str(site.id),
            "onion_address": site.onion_address,
            "title": site.title,
            "description": site.description,
            "category": site.category,
            "risk_level": site.risk_level,
            "risk_score": site.risk_score,
            "status": site.status,
            "first_seen": site.first_seen.isoformat() if site.first_seen else None,
            "last_checked": site.last_checked.isoformat() if site.last_checked else None,
            "requires_review": site.requires_review,
            "is_honeypot": site.is_honeypot,
            "metadata": site.metadata,
            "classifications": [dict(row._mapping) for row in classifications.fetchall()],
            "safety_checks": [dict(row._mapping) for row in safety_checks.fetchall()],
        }


@app.post("/api/sites/search", tags=["Sites"])
async def search_sites(
    query: SearchQuery,
    db: Database = Depends(get_db),
    token: str = Depends(verify_token),
):
    """Search sites."""
    async with db.get_session() as session:
        # Build WHERE clause
        conditions = []
        params = {}
        
        if query.query:
            conditions.append("(onion_address ILIKE :query OR title ILIKE :query OR description ILIKE :query)")
            params['query'] = f"%{query.query}%"
        
        if query.category:
            conditions.append("category = :category")
            params['category'] = query.category
        
        if query.risk_level:
            conditions.append("risk_level = :risk_level")
            params['risk_level'] = query.risk_level
        
        if query.status:
            conditions.append("status = :status")
            params['status'] = query.status
        
        where_clause = " AND ".join(conditions) if conditions else "1=1"
        
        # Build query
        sql = f"""
            SELECT * FROM sites
            WHERE {where_clause}
            ORDER BY last_checked DESC NULLS FIRST
            LIMIT :limit OFFSET :offset
        """
        
        params['limit'] = query.limit
        params['offset'] = query.offset
        
        result = await session.execute(sql, params)
        sites = [dict(row._mapping) for row in result.fetchall()]
        
        # Get total count
        count_sql = f"SELECT COUNT(*) FROM sites WHERE {where_clause}"
        count_result = await session.execute(count_sql, params)
        total = count_result.scalar() or 0
        
        return {
            "sites": sites,
            "total": total,
            "limit": query.limit,
            "offset": query.offset,
        }


@app.post("/api/classify", tags=["Classification"])
async def classify_content(
    request: ClassificationRequest,
    background_tasks: BackgroundTasks,
    pipeline: ClassificationPipeline = Depends(get_pipeline),
    plugins: PluginManager = Depends(get_plugins),
    token: str = Depends(verify_token),
):
    """Classify content."""
    try:
        result = await pipeline.process(
            url=request.url or "unknown",
            content=request.content,
            content_type_hint=request.content_type,
        )
        
        # Emit event if classification successful
        if result.classification_result:
            event = EventData(
                event_type=PluginEvent.SITE_CLASSIFIED,
                timestamp=datetime.now().timestamp(),
                data=result.to_dict(),
            )
            background_tasks.add_task(plugins.emit_event, event)
        
        return result.to_dict()
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/plugins", tags=["Plugins"])
async def list_plugins(
    plugins: PluginManager = Depends(get_plugins),
    token: str = Depends(verify_token),
):
    """List all plugins."""
    return plugins.list_plugins()


@app.post("/api/plugins/{plugin_name}/enable", tags=["Plugins"])
async def enable_plugin(
    plugin_name: str,
    plugins: PluginManager = Depends(get_plugins),
    token: str = Depends(verify_token),
):
    """Enable a plugin."""
    plugin = plugins.get_plugin(plugin_name)
    if not plugin:
        raise HTTPException(status_code=404, detail="Plugin not found")
    
    plugin.enabled = True
    return {"status": "enabled", "plugin": plugin_name}


@app.post("/api/plugins/{plugin_name}/disable", tags=["Plugins"])
async def disable_plugin(
    plugin_name: str,
    plugins: PluginManager = Depends(get_plugins),
    token: str = Depends(verify_token),
):
    """Disable a plugin."""
    plugin = plugins.get_plugin(plugin_name)
    if not plugin:
        raise HTTPException(status_code=404, detail="Plugin not found")
    
    plugin.enabled = False
    return {"status": "disabled", "plugin": plugin_name}


@app.post("/api/discover", tags=["Discovery"])
async def trigger_discovery(
    background_tasks: BackgroundTasks,
    seeds: Optional[List[str]] = Query(None),
    depth: int = Query(2),
    limit: int = Query(100),
    db: Database = Depends(get_db),
    token: str = Depends(verify_token),
):
    """Trigger discovery process."""
    from src.core.tor_manager import create_tor_manager
    from src.discovery.orchestrator import DiscoveryOrchestrator, DiscoveryConfig
    
    config = load_config()
    
    async def run_discovery():
        """Run discovery in background."""
        try:
            tor_manager = create_tor_manager(config.dict())
            tor_manager.start()
            
            discovery_config = DiscoveryConfig(
                mode='crawl',
                max_depth=depth,
                max_new_sites=limit,
            )
            
            orchestrator = DiscoveryOrchestrator(tor_manager, db, discovery_config)
            
            if seeds:
                seed_urls = seeds
            else:
                # Use default seeds
                seed_file = config.discovery.seeds_file
                with open(seed_file, 'r') as f:
                    seed_urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            
            results = await orchestrator.discover(seed_urls=seed_urls)
            
            tor_manager.stop()
            
            logger.info(f"Discovery completed: {results}")
            
        except Exception as e:
            logger.error(f"Discovery failed: {e}")
    
    background_tasks.add_task(run_discovery)
    
    return {
        "status": "started",
        "message": "Discovery process started in background",
        "timestamp": datetime.now().isoformat(),
    }


@app.get("/api/export/{format}", tags=["Export"])
async def export_data(
    format: str,
    query: SearchQuery = Depends(),
    db: Database = Depends(get_db),
    token: str = Depends(verify_token),
):
    """Export data in various formats."""
    async with db.get_session() as session:
        # Get sites based on query
        conditions = []
        params = {}
        
        if query.query:
            conditions.append("(onion_address ILIKE :query OR title ILIKE :query OR description ILIKE :query)")
            params['query'] = f"%{query.query}%"
        
        if query.category:
            conditions.append("category = :category")
            params['category'] = query.category
        
        where_clause = " AND ".join(conditions) if conditions else "1=1"
        
        sql = f"""
            SELECT * FROM sites
            WHERE {where_clause}
            ORDER BY last_checked DESC
            LIMIT :limit
        """
        
        params['limit'] = query.limit
        
        result = await session.execute(sql, params)
        sites = [dict(row._mapping) for row in result.fetchall()]
        
        # Export based on format
        if format == "json":
            return sites
        
        elif format == "csv":
            import csv
            import io
            
            output = io.StringIO()
            if sites:
                writer = csv.DictWriter(output, fieldnames=sites[0].keys())
                writer.writeheader()
                writer.writerows(sites)
            
            return output.getvalue()
        
        elif format == "graphml":
            # Export as GraphML for network analysis
            return export_graphml(sites)
        
        else:
            raise HTTPException(status_code=400, detail=f"Unsupported format: {format}")


def export_graphml(sites: List[Dict[str, Any]]) -> str:
    """Export sites as GraphML.
    
    Args:
        sites: List of site data
        
    Returns:
        GraphML XML string
    """
    import xml.etree.ElementTree as ET
    from xml.dom import minidom
    
    # Create GraphML root
    graphml = ET.Element("graphml", {
        "xmlns": "http://graphml.graphdrawing.org/xmlns",
        "xmlns:xsi": "http://www.w3.org/2001/XMLSchema-instance",
        "xsi:schemaLocation": "http://graphml.graphdrawing.org/xmlns http://graphml.graphdrawing.org/xmlns/1.0/graphml.xsd",
    })
    
    # Define attributes
    node_attrs = [
        ("category", "string"),
        ("risk_level", "string"),
        ("risk_score", "float"),
    ]
    
    for attr_name, attr_type in node_attrs:
        ET.SubElement(graphml, "key", {
            "id": attr_name,
            "for": "node",
            "attr.name": attr_name,
            "attr.type": attr_type,
        })
    
    # Create graph
    graph = ET.SubElement(graphml, "graph", {
        "id": "G",
        "edgedefault": "directed",
    })
    
    # Add nodes
    for i, site in enumerate(sites):
        node = ET.SubElement(graph, "node", {"id": f"n{i}"})
        
        # Add data elements
        for attr_name, _ in node_attrs:
            if attr_name in site and site[attr_name]:
                ET.SubElement(node, "data", {"key": attr_name}).text = str(site[attr_name])
    
    # Convert to pretty XML
    rough_string = ET.tostring(graphml, 'utf-8')
    parsed = minidom.parseString(rough_string)
    
    return parsed.toprettyxml(indent="  ")


# ==================== WebSocket Events ====================

from fastapi import WebSocket, WebSocketDisconnect

class ConnectionManager:
    """Manages WebSocket connections."""
    
    def __init__(self):
        self.active_connections: List[WebSocket] = []
    
    async def connect(self, websocket: WebSocket):
        """Connect WebSocket."""
        await websocket.accept()
        self.active_connections.append(websocket)
    
    def disconnect(self, websocket: WebSocket):
        """Disconnect WebSocket."""
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
    
    async def broadcast(self, message: Dict[str, Any]):
        """Broadcast message to all connections."""
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception:
                self.disconnect(connection)

manager = ConnectionManager()

@app.websocket("/api/ws/events")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint for real-time events."""
    await manager.connect(websocket)
    
    try:
        while True:
            # Keep connection alive
            await websocket.receive_text()
            
    except WebSocketDisconnect:
        manager.disconnect(websocket)


# ==================== CLI Entry Point ====================

def run_api(host: str = "0.0.0.0", port: int = 8000):
    """Run the API server."""
    setup_logger(level="INFO")
    
    logger.info(f"Starting Arachne API on {host}:{port}")
    logger.info(f"API Documentation: http://{host}:{port}/api/docs")
    
    uvicorn.run(
        app,
        host=host,
        port=port,
        log_level="info",
    )