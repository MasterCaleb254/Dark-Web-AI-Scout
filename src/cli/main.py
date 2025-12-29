"""
Command Line Interface for Arachne.
"""

import click
import asyncio
from typing import Optional, List
from pathlib import Path

from src.utils.logger import setup_logger, get_logger
from src.utils.config import load_config
from src.core.tor_manager import create_tor_manager
from src.storage.database import create_database
from src.discovery.orchestrator import DiscoveryOrchestrator, DiscoveryConfig, DiscoveryMode
from src.discovery.harvester import OnionHarvester

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
    click.echo("  discover - Discovery commands")
    click.echo("  db       - Database operations")
    click.echo("  status   - Show this status")


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


if __name__ == '__main__':
    cli()
