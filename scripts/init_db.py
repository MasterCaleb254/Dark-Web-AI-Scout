#!/usr/bin/env python3
"""
Initialize Arachne database.
"""

import asyncio
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.utils.logger import setup_logger, get_logger
from src.utils.config import load_config
from src.storage.database import create_database
from src.storage.models import Base

logger = get_logger(__name__)


async def init_database():
    """Initialize database tables and basic data."""
    setup_logger(level="INFO")
    
    try:
        # Load configuration
        config = load_config()
        
        logger.info("Initializing database...")
        
        # Create database connection
        db = await create_database(config.database)
        
        async with db.get_session() as session:
            # Create tables (already done in connect, but ensure)
            await session.run_sync(Base.metadata.create_all)
            
            # Insert any initial data here
            # Example: Insert default system user, configuration, etc.
            
            await session.commit()
        
        logger.info("Database initialized successfully")
        
        # Close connections
        await db.disconnect()
        
    except Exception as e:
        logger.error(f"Failed to initialize database: {e}")
        sys.exit(1)


async def drop_database():
    """Drop all database tables (for development)."""
    setup_logger(level="WARNING")
    
    config = load_config()
    db = await create_database(config.database)
    
    async with db.get_session() as session:
        confirmation = input("This will DROP ALL TABLES. Type 'DROP' to confirm: ")
        if confirmation == "DROP":
            await session.run_sync(Base.metadata.drop_all)
            await session.commit()
            logger.warning("All tables dropped")
        else:
            logger.info("Operation cancelled")
    
    await db.disconnect()


async def reset_database():
    """Reset database (drop and recreate)."""
    setup_logger(level="WARNING")
    
    config = load_config()
    db = await create_database(config.database)
    
    async with db.get_session() as session:
        confirmation = input("This will RESET ALL DATA. Type 'RESET' to confirm: ")
        if confirmation == "RESET":
            await session.run_sync(Base.metadata.drop_all)
            await session.run_sync(Base.metadata.create_all)
            await session.commit()
            logger.warning("Database reset complete")
        else:
            logger.info("Operation cancelled")
    
    await db.disconnect()


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Database management")
    parser.add_argument("action", choices=["init", "drop", "reset"], default="init")
    
    args = parser.parse_args()
    
    if args.action == "init":
        asyncio.run(init_database())
    elif args.action == "drop":
        asyncio.run(drop_database())
    elif args.action == "reset":
        asyncio.run(reset_database())
