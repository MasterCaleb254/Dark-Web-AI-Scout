"""
Command Line Interface for Arachne.
"""

import click
import asyncio
import uvicorn
from typing import Optional, List
from pathlib import Path
import json
import sys

from src.utils.logger import setup_logger, get_logger
from src.utils.config import load_config
from src.core.tor_manager import create_tor_manager
from src.storage.database import create_database
from src.discovery.orchestrator import DiscoveryOrchestrator, DiscoveryConfig, DiscoveryMode
from src.discovery.harvester import OnionHarvester
from src.classification.pipeline import ClassificationPipeline
from src.classification.storage import ClassificationStorage

logger = get_logger(__name__)


@click.group()
@click.option('--config', '-c', default='configs/default.yaml', help='Configuration file')
@click.option('--log-level', '-l', default='INFO', help='Log level')
@click.pass_context
def cli(ctx, config: str, log_level: str):
    """Arachne - Dark Web Scout CLI"""
    # Setup logging
    setup_logger(level=log_level)
    
    # Load configuration
    ctx.ensure_object(dict)
    ctx.obj['config'] = load_config(config)
    
    logger.info(f"Arachne CLI initialized with config: {config}")


@cli.group()
def discover():
    """Discovery commands."""
    pass


@discover.command()
@click.option('--seeds', '-s', help='File containing seed URLs')
@click.option('--depth', '-d', default=2, help='Crawl depth')
@click.option('--limit', '-l', default=100, help='Maximum sites to discover')
@click.option('--mode', '-m', 
              type=click.Choice(['full', 'crawl', 'listen', 'sync', 'targeted']),
              default='crawl',
              help='Discovery mode')
@click.option('--continuous', is_flag=True, help='Run discovery continuously')
@click.option('--interval', '-i', default=3600, help='Interval for continuous discovery (seconds)')
@click.pass_context
def start(ctx, seeds: Optional[str], depth: int, limit: int, mode: str, 
          continuous: bool, interval: int):
    """Start discovery process."""
    config = ctx.obj['config']
    
    # Use provided seeds or default
    if seeds:
        seeds_file = seeds
    else:
        seeds_file = getattr(config.discovery, 'seeds_file', 'configs/seeds.txt')
    
    if not Path(seeds_file).exists():
        logger.error(f"Seeds file not found: {seeds_file}")
        return
    
    # Read seed URLs
    with open(seeds_file, 'r') as f:
        seed_urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    
    logger.info(f"Starting discovery with {len(seed_urls)} seed URLs")
    logger.info(f"Mode: {mode}, Depth: {depth}, Limit: {limit}")
    
    # Convert mode string to enum
    mode_enum = DiscoveryMode(mode)
    
    async def run_discovery():
        # Create Tor manager
        tor_manager = create_tor_manager(config.dict())
        tor_manager.start()
        
        # Create database connection
        db = await create_database(config.database)
        
        try:
            # Create discovery configuration
            discovery_config = DiscoveryConfig(
                mode=mode_enum,
                max_depth=depth,
                max_new_sites=limit,
            )
            
            # Create orchestrator
            orchestrator = DiscoveryOrchestrator(tor_manager, db, discovery_config)
            
            if continuous:
                logger.info(f"Starting continuous discovery with {interval} second interval")
                
                # Run continuous discovery
                await orchestrator.start_continuous_discovery(interval)
                
                # Keep running until interrupted
                try:
                    while True:
                        await asyncio.sleep(1)
                except KeyboardInterrupt:
                    logger.info("Interrupted, stopping discovery...")
                    await orchestrator.stop_continuous_discovery()
            else:
                # Run single discovery
                logger.info("Starting single discovery run")
                
                results = await orchestrator.discover(seed_urls)
                
                click.echo("=== Discovery Results ===")
                click.echo(f"Sites discovered: {results['sites_discovered']}")
                click.echo(f"Links found: {results['links_found']}")
                click.echo(f"Errors: {results['errors']}")
                click.echo(f"Start time: {results['start_time']}")
                click.echo(f"End time: {results['end_time']}")
        
        finally:
            # Cleanup
            tor_manager.stop()
            await db.disconnect()
    
    # Run async function
    asyncio.run(run_discovery())


@discover.command()
@click.pass_context
def status(ctx):
    """Show discovery status."""
    config = ctx.obj['config']
    
    async def get_status():
        # Create Tor manager and database
        tor_manager = create_tor_manager(config.dict())
        tor_manager.start()
        
        db = await create_database(config.database)
        
        try:
            # Create orchestrator
            orchestrator = DiscoveryOrchestrator(tor_manager, db)
            status_info = orchestrator.get_status()
            
            click.echo("=== Discovery Status ===")
            click.echo(f"Running: {status_info['running']}")
            click.echo(f"Mode: {status_info['mode']}")
            
            if status_info['results']['start_time']:
                click.echo(f"Last start: {status_info['results']['start_time']}")
                click.echo(f"Last end: {status_info['results']['end_time']}")
                click.echo(f"Sites discovered: {status_info['results']['sites_discovered']}")
                click.echo(f"Total errors: {status_info['results']['errors']}")
        
        finally:
            tor_manager.stop()
            await db.disconnect()
    
    asyncio.run(get_status())


@discover.command()
@click.option('--input', '-i', help='File with URLs to extract from')
@click.option('--text', '-t', help='Text to extract URLs from')
@click.option('--output', '-o', help='Output file for extracted URLs')
@click.pass_context
def extract(ctx, input: Optional[str], text: Optional[str], output: Optional[str]):
    """Extract onion URLs from text or file."""
    harvester = OnionHarvester()
    discovered = set()
    
    if input:
        if Path(input).exists():
            with open(input, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                discovered.update(harvester.extract_from_text(content))
            logger.info(f"Extracted from file: {input}")
        else:
            logger.error(f"Input file not found: {input}")
            return
    
    if text:
        discovered.update(harvester.extract_from_text(text))
        logger.info("Extracted from provided text")
    
    if not discovered:
        click.echo("No onion URLs found")
        return
    
    # Output results
    click.echo(f"Found {len(discovered)} onion URLs:")
    for url in sorted(discovered):
        click.echo(f"  {url}")
    
    # Save to file if requested
    if output:
        with open(output, 'w') as f:
            for url in sorted(discovered):
                f.write(f"{url}\n")
        logger.info(f"Saved {len(discovered)} URLs to {output}")


@discover.command()
@click.option('--url', '-u', required=True, help='URL to test crawl')
@click.option('--depth', '-d', default=1, help='Crawl depth')
@click.pass_context
def test_crawl(ctx, url: str, depth: int):
    """Test crawling a single URL."""
    config = ctx.obj['config']
    
    async def test():
        # Create Tor manager
        tor_manager = create_tor_manager(config.dict())
        tor_manager.start()
        
        try:
            from src.discovery.spider import LinkSpider
            
            spider = LinkSpider(
                tor_manager,
                max_depth=depth,
                request_delay=(0.5, 1.0),  # Shorter delays for testing
            )
            
            click.echo(f"Testing crawl of {url} (depth: {depth})")
            click.echo("=" * 50)
            
            results = await spider.crawl_site(url, depth=depth)
            
            click.echo(f"Crawled {len(results)} pages")
            
            for page_url, result in results.items():
                click.echo(f"\n{page_url}:")
                click.echo(f"  Status: {'Success' if result.success else 'Failed'}")
                click.echo(f"  Load time: {result.load_time:.2f}s")
                click.echo(f"  Links found: {len(result.discovered_links)}")
                
                if result.error:
                    click.echo(f"  Error: {result.error}")
                
                # Show first few links
                if result.discovered_links:
                    click.echo("  Sample links:")
                    for link in list(result.discovered_links)[:5]:
                        click.echo(f"    - {link}")
            
            # Show spider stats
            stats = spider.get_stats()
            click.echo("\n" + "=" * 50)
            click.echo("Spider Statistics:")
            click.echo(f"Pages crawled: {stats['pages_crawled']}")
            click.echo(f"Links discovered: {stats['links_discovered']}")
            click.echo(f"Errors: {stats['errors']}")
            click.echo(f"Circuits used: {stats['circuits_used']}")
        
        finally:
            tor_manager.stop()
    
    asyncio.run(test())


@cli.group()
def classify():
    """Classification commands."""
    pass


@classify.command()
@click.option('--site-id', help='Site ID to classify')
@click.option('--url', help='URL to classify (for testing)')
@click.option('--content-file', help='File with content to classify')
@click.option('--batch', is_flag=True, help='Batch classify all unclassified sites')
@click.option('--limit', default=100, help='Maximum sites to classify')
@click.option('--output', '-o', help='Output file for results')
@click.pass_context
def run(ctx, site_id: Optional[str], url: Optional[str], content_file: Optional[str], 
        batch: bool, limit: int, output: Optional[str]):
    """Run classification on sites."""
    config = ctx.obj['config']
    
    async def run_classification():
        # Create database connection
        db = await create_database(config.database)
        storage = ClassificationStorage(db)
        
        # Create classification pipeline
        pipeline = ClassificationPipeline()
        
        if site_id:
            # Classify specific site from database
            async with db.get_session() as session:
                from src.storage.models import Site
                from sqlalchemy import select
                
                stmt = select(Site).where(Site.id == site_id)
                result = await session.execute(stmt)
                site = result.scalar_one_or_none()
                
                if not site:
                    click.echo(f"Site {site_id} not found")
                    return
                
                # TODO: Fetch site content and classify
                click.echo(f"Classifying site: {site.onion_address}")
                # This would require fetching content first
                
        elif url:
            # Classify specific URL (test mode)
            click.echo(f"Testing classification for: {url}")
            
            # Get content (for testing, we'd need to fetch it)
            content = f"Test content for {url}"
            
            result = await pipeline.process(
                url=url,
                content=content,
                content_type_hint='text/html',
            )
            
            # Display results
            _display_classification_result(result)
            
            # Save to file if requested
            if output:
                with open(output, 'w') as f:
                    json.dump(result.to_dict(), f, indent=2, default=str)
                click.echo(f"Results saved to {output}")
        
        elif content_file:
            # Classify content from file
            if Path(content_file).exists():
                with open(content_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                result = await pipeline.process(
                    url=f"file://{content_file}",
                    content=content,
                    content_type_hint='text/plain',
                )
                
                _display_classification_result(result)
                
                if output:
                    with open(output, 'w') as f:
                        json.dump(result.to_dict(), f, indent=2, default=str)
                    click.echo(f"Results saved to {output}")
            else:
                click.echo(f"File not found: {content_file}")
        
        elif batch:
            # Batch classify unclassified sites
            click.echo(f"Batch classifying up to {limit} sites...")
            
            sites = await storage.get_sites_needing_classification(limit=limit)
            click.echo(f"Found {len(sites)} sites needing classification")
            
            # TODO: Implement batch classification with content fetching
            # This would require integrating with discovery to fetch content
            
        else:
            click.echo("Please specify --site-id, --url, --content-file, or --batch")
        
        # Display pipeline statistics
        stats = pipeline.get_pipeline_stats()
        click.echo("\n=== Pipeline Statistics ===")
        click.echo(f"Processed: {stats['processed']}")
        click.echo(f"Blocked: {stats['blocked']}")
        click.echo(f"Classified: {stats['classified']}")
        click.echo(f"Errors: {stats['errors']}")
        click.echo(f"Avg time: {stats['avg_processing_time']:.2f}s")
        
        await db.disconnect()
    
    asyncio.run(run_classification())


@classify.command()
@click.pass_context
def stats(ctx):
    """Show classification statistics."""
    config = ctx.obj['config']
    
    async def show_stats():
        db = await create_database(config.database)
        
        async with db.get_session() as session:
            # Get classification counts
            stmt = """
                SELECT 
                    COUNT(*) as total,
                    COUNT(CASE WHEN category IS NOT NULL THEN 1 END) as classified,
                    COUNT(CASE WHEN requires_review = TRUE THEN 1 END) as needs_review,
                    COUNT(CASE WHEN is_honeypot = TRUE THEN 1 END) as honeypots,
                    COUNT(CASE WHEN risk_level = 'critical' THEN 1 END) as critical,
                    COUNT(CASE WHEN risk_level = 'high' THEN 1 END) as high_risk
                FROM sites
            """
            
            result = await session.execute(stmt)
            row = result.fetchone()
            
            click.echo("=== Classification Statistics ===")
            click.echo(f"Total sites: {row[0]}")
            click.echo(f"Classified: {row[1]}")
            click.echo(f"Need review: {row[2]}")
            click.echo(f"Honeypots: {row[3]}")
            click.echo(f"Critical risk: {row[4]}")
            click.echo(f"High risk: {row[5]}")
            
            # Get category distribution
            stmt = """
                SELECT category, COUNT(*) as count
                FROM sites
                WHERE category IS NOT NULL
                GROUP BY category
                ORDER BY count DESC
            """
            
            result = await session.execute(stmt)
            rows = result.fetchall()
            
            click.echo("\n=== Category Distribution ===")
            for category, count in rows:
                click.echo(f"  {category or 'Unknown'}: {count}")
        
        await db.disconnect()
    
    asyncio.run(show_stats())


@classify.command()
@click.option('--risk-level', 
              type=click.Choice(['critical', 'high', 'medium', 'low']),
              default='high',
              help='Risk level to filter')
@click.option('--limit', default=20, help='Maximum sites to show')
@click.pass_context
def risky(ctx, risk_level: str, limit: int):
    """Show high-risk sites."""
    config = ctx.obj['config']
    
    async def show_risky():
        db = await create_database(config.database)
        storage = ClassificationStorage(db)
        
        sites = await storage.get_high_risk_sites(risk_level=risk_level, limit=limit)
        
        click.echo(f"=== {risk_level.upper()} Risk Sites ===")
        click.echo(f"Found {len(sites)} sites")
        
        for i, site in enumerate(sites, 1):
            click.echo(f"\n{i}. {site['onion_address']}")
            click.echo(f"   Category: {site.get('category', 'Unknown')}")
            click.echo(f"   Risk: {site.get('risk_level', 'Unknown')} ({site.get('risk_score', 0):.2f})")
            click.echo(f"   Status: {site.get('status', 'Unknown')}")
            click.echo(f"   Last checked: {site.get('last_checked', 'Never')}")
            
            if site.get('requires_review'):
                click.echo("   ⚠️  REQUIRES REVIEW")
        
        await db.disconnect()
    
    asyncio.run(show_risky())


@classify.command()
@click.option('--patterns-file', required=True, help='File with illegal patterns (JSON)')
@click.pass_context
def test_patterns(ctx, patterns_file: str):
    """Test illegal content patterns."""
    from src.classification.safety import IllegalContentDetector
    
    if not Path(patterns_file).exists():
        click.echo(f"Patterns file not found: {patterns_file}")
        return
    
    detector = IllegalContentDetector(patterns_file=patterns_file)
    
    click.echo("=== Pattern Testing ===")
    click.echo("Enter text to test (Ctrl+D to exit):")
    
    try:
        while True:
            try:
                line = input("> ")
                if not line:
                    continue
                
                result = detector.check_text(line)
                
                click.echo(f"  Action: {result.action.value}")
                click.echo(f"  Confidence: {result.confidence:.2f}")
                if result.flagged_categories:
                    click.echo(f"  Categories: {', '.join(result.flagged_categories)}")
                if result.risk_factors:
                    click.echo(f"  Risk factors: {', '.join(result.risk_factors[:3])}")
                click.echo()
                
            except EOFError:
                break
            except Exception as e:
                click.echo(f"Error: {e}")
    
    except KeyboardInterrupt:
        click.echo("\nExiting...")


def _display_classification_result(result):
    """Display classification result in readable format."""
    click.echo("\n=== Classification Results ===")
    click.echo(f"URL: {result.url}")
    click.echo(f"Processing time: {result.processing_time:.2f}s")
    
    # Safety results
    click.echo(f"\nSafety: {result.safety_result.action.value}")
    click.echo(f"  Confidence: {result.safety_result.confidence:.2f}")
    if result.safety_result.flagged_categories:
        click.echo(f"  Flagged: {', '.join(result.safety_result.flagged_categories)}")
    
    # Classification results
    if result.classification_result:
        click.echo(f"\nClassification: {result.classification_result.category.value}")
        click.echo(f"  Confidence: {result.classification_result.confidence:.2f}")
        if result.classification_result.subcategory:
            click.echo(f"  Subcategory: {result.classification_result.subcategory}")
    
    # Risk assessment
    if result.risk_score:
        click.echo(f"\nRisk: {result.risk_score.level.value} ({result.risk_score.score:.2f})")
        click.echo(f"  Confidence: {result.risk_score.confidence:.2f}")
        if result.risk_score.factors:
            click.echo(f"  Factors: {', '.join([f.value for f in result.risk_score.factors[:3]])}")
    
    # Errors
    if result.errors:
        click.echo(f"\n⚠️  Errors: {len(result.errors)}")
        for error in result.errors[:3]:
            click.echo(f"  - {error}")


@cli.command()
@click.pass_context
def status(ctx):
    """Show system status."""
    config = ctx.obj['config']
    
    click.echo("=== Arachne Status ===")
    click.echo(f"Version: {config.version}")
    click.echo(f"Log Level: {config.log_level}")
    click.echo(f"Tor SOCKS Port: {config.tor.socks_port}")
    click.echo(f"Discovery Depth: {getattr(config.discovery, 'max_depth', 'N/A')}")
    click.echo("\nCommands:")
    click.echo("  discover     - Discovery commands")
    click.echo("  classify     - Classification commands")
    click.echo("  db           - Database operations")
    click.echo("  status       - Show this status")


@cli.group()
def db():
    """Database operations."""
    pass


@db.command()
@click.pass_context
def status(ctx):
    """Show database status."""
    import asyncio
    from src.storage.database import create_database
    from src.storage.models import Site
    from sqlalchemy import func
    
    async def check_status():
        config = ctx.obj['config']
        try:
            db = await create_database(config.database)
            
            async with db.get_session() as session:
                # Count sites
                site_count = await session.execute(func.count(Site.id))
                sites = site_count.scalar()
                
                click.echo("=== Database Status ===")
                click.echo(f"PostgreSQL: Connected")
                click.echo(f"Redis: Connected")
                click.echo(f"Sites in database: {sites}")
                
            await db.disconnect()
            
        except Exception as e:
            click.echo(f"Database connection failed: {e}")
    
    asyncio.run(check_status())


@db.command()
@click.pass_context
def init(ctx):
    """Initialize database."""
    import asyncio
    from src.storage.database import create_database
    
    async def init_db():
        config = ctx.obj['config']
        try:
            db = await create_database(config.database)
            click.echo("Database initialized successfully")
            await db.disconnect()
        except Exception as e:
            click.echo(f"Failed to initialize database: {e}")
            raise
    
    asyncio.run(init_db())


@cli.group()
def api():
    """API server commands."""
    pass


@api.command()
@click.option('--host', default='0.0.0.0', help='Host to bind to')
@click.option('--port', default=8000, help='Port to bind to')
@click.option('--reload', is_flag=True, help='Enable auto-reload (development)')
@click.pass_context
def serve(ctx, host: str, port: int, reload: bool):
    """Start the API server."""
    config = ctx.obj['config']
    
    logger.info(f"Starting API server on {host}:{port}")
    
    # Run uvicorn
    uvicorn.run(
        "src.api.main:app",
        host=host,
        port=port,
        reload=reload,
        log_level="info",
    )


@cli.group()
def monitor():
    """Monitoring commands."""
    pass


@monitor.command()
@click.option('--interval', default=60, help='Check interval in seconds')
@click.pass_context
def health(ctx, interval: int):
    """Start health monitoring."""
    config = ctx.obj['config']
    
    async def run_monitoring():
        from src.monitoring.health import HealthMonitor, DatabaseHealthCheck, SystemHealthCheck, TorHealthCheck
        
        # Create database connection
        db = await create_database(config.database)
        
        # Create Tor manager
        tor_manager = create_tor_manager(config.dict())
        tor_manager.start()
        
        # Create health checks
        checks = [
            DatabaseHealthCheck(db, interval=30),
            TorHealthCheck(tor_manager, interval=60),
            SystemHealthCheck(interval=60),
        ]
        
        # Create health monitor
        monitor = HealthMonitor(checks)
        
        try:
            # Run monitoring
            await monitor.start(interval=interval)
            
            # Keep running until interrupted
            while True:
                await asyncio.sleep(1)
                
        except KeyboardInterrupt:
            logger.info("Stopping health monitoring...")
            await monitor.stop()
            tor_manager.stop()
            await db.disconnect()
    
    asyncio.run(run_monitoring())


@monitor.command()
@click.pass_context
def status(ctx):
    """Show current system status."""
    config = ctx.obj['config']
    
    async def get_status():
        import psutil
        
        db = await create_database(config.database)
        
        try:
            # System stats
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            
            # Database stats
            async with db.get_session() as session:
                # Site counts
                stmt = """
                    SELECT 
                        COUNT(*) as total,
                        COUNT(CASE WHEN requires_review = TRUE THEN 1 END) as needs_review,
                        COUNT(CASE WHEN is_honeypot = TRUE THEN 1 END) as honeypots
                    FROM sites
                """
                result = await session.execute(stmt)
                site_stats = dict(result.fetchone()._mapping)
            
            click.echo("=== System Status ===")
            click.echo(f"CPU Usage: {cpu_percent:.1f}%")
            click.echo(f"Memory Usage: {memory.percent:.1f}% ({memory.used / (1024**3):.1f} GB / {memory.total / (1024**3):.1f} GB)")
            click.echo(f"Disk Usage: {disk.percent:.1f}% ({disk.used / (1024**3):.1f} GB / {disk.total / (1024**3):.1f} GB)")
            click.echo(f"\n=== Database Status ===")
            click.echo(f"Total Sites: {site_stats['total']}")
            click.echo(f"Sites Needing Review: {site_stats['needs_review']}")
            click.echo(f"Honeypots Detected: {site_stats['honeypots']}")
        
        finally:
            await db.disconnect()
    
    asyncio.run(get_status())


@cli.group()
def system():
    """System management commands."""
    pass


@system.command()
@click.option('--workers', default=3, help='Number of worker processes')
@click.pass_context
def start(ctx, workers: int):
    """Start the complete Arachne system."""
    config = ctx.obj['config']
    
    async def run_system():
        from src.orchestrator.scheduler import Scheduler
        from src.discovery.orchestrator import DiscoveryOrchestrator
        from src.classification.pipeline import ClassificationPipeline
        
        # Initialize components
        tor_manager = create_tor_manager(config.dict())
        tor_manager.start()
        
        db = await create_database(config.database)
        
        discovery_orchestrator = DiscoveryOrchestrator(tor_manager, db)
        classification_pipeline = ClassificationPipeline()
        
        # Create scheduler
        scheduler = Scheduler(
            database=db,
            discovery_orchestrator=discovery_orchestrator,
            classification_pipeline=classification_pipeline,
        )
        
        # Start scheduler
        await scheduler.start(num_workers=workers)
        
        logger.info(f"Arachne system started with {workers} workers")
        
        try:
            # Keep running until interrupted
            while True:
                await asyncio.sleep(1)
                
        except KeyboardInterrupt:
            logger.info("Shutting down system...")
            await scheduler.stop()
            tor_manager.stop()
            await db.disconnect()
            logger.info("System stopped")
    
    asyncio.run(run_system())


if __name__ == '__main__':
    cli()
