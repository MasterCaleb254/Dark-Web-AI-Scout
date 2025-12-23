"""
Command Line Interface for Arachne.
"""

import click
from typing import Optional
from pathlib import Path

from src.utils.logger import setup_logger, get_logger
from src.utils.config import load_config

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


@cli.command()
@click.option('--seeds', '-s', help='File containing seed URLs')
@click.option('--depth', '-d', default=2, help='Crawl depth')
@click.pass_context
def discover(ctx, seeds: Optional[str], depth: int):
    """Discover new dark web sites."""
    config = ctx.obj['config']
    
    # Use provided seeds or default
    if seeds:
        seeds_file = seeds
    else:
        seeds_file = config.discovery.seeds_file
    
    if not Path(seeds_file).exists():
        logger.error(f"Seeds file not found: {seeds_file}")
        return
    
    logger.info(f"Starting discovery with seeds from {seeds_file}")
    logger.info(f"Maximum depth: {depth}")
    
    # TODO: Implement discovery logic
    click.echo("Discovery command not yet implemented")


@cli.command()
@click.option('--site-id', help='Site ID to classify')
@click.option('--batch', is_flag=True, help='Batch classify all unclassified sites')
@click.pass_context
def classify(ctx, site_id: Optional[str], batch: bool):
    """Classify discovered sites."""
    config = ctx.obj['config']
    
    if site_id:
        logger.info(f"Classifying site: {site_id}")
        # TODO: Single site classification
    elif batch:
        logger.info("Batch classifying all unclassified sites")
        # TODO: Batch classification
    else:
        logger.error("Either --site-id or --batch must be specified")
        return
    
    click.echo("Classification command not yet implemented")


@cli.command()
@click.pass_context
def status(ctx):
    """Show system status."""
    config = ctx.obj['config']
    
    click.echo("=== Arachne Status ===")
    click.echo(f"Version: {config.version}")
    click.echo(f"Log Level: {config.log_level}")
    click.echo(f"Tor SOCKS Port: {config.tor.socks_port}")
    click.echo(f"Discovery Depth: {config.discovery.max_depth}")
    click.echo("\nCommands:")
    click.echo("  discover - Discover new sites")
    click.echo("  classify - Classify discovered sites")
    click.echo("  status   - Show this status")


@cli.command()
@click.pass_context
def init_db(ctx):
    """Initialize database."""
    from src.storage.database import init_database
    
    config = ctx.obj['config']
    logger.info("Initializing database...")
    
    try:
        init_database(config.database)
        logger.info("Database initialized successfully")
    except Exception as e:
        logger.error(f"Failed to initialize database: {e}")
        raise


if __name__ == '__main__':
    cli()
