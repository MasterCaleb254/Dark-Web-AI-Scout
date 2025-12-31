"""
Scheduler for discovery and classification tasks.
"""

import asyncio
import time
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
from enum import Enum
import logging

from src.utils.logger import get_logger
from src.utils.config import load_config
from src.storage.database import Database, CrawlJobRepository, SiteRepository
from src.discovery.orchestrator import DiscoveryOrchestrator, DiscoveryConfig, DiscoveryMode
from src.classification.pipeline import ClassificationPipeline
from src.classification.storage import ClassificationStorage

logger = get_logger(__name__)


class TaskType(Enum):
    """Types of tasks that can be scheduled."""
    DISCOVERY = "discovery"
    CLASSIFICATION = "classification"
    MAINTENANCE = "maintenance"


class TaskPriority(Enum):
    """Priority levels for tasks."""
    LOW = 0
    MEDIUM = 5
    HIGH = 10
    CRITICAL = 15


class Scheduler:
    """Schedules and manages background tasks."""
    
    def __init__(
        self,
        database: Database,
        discovery_orchestrator: DiscoveryOrchestrator,
        classification_pipeline: ClassificationPipeline,
        config: Optional[Dict[str, Any]] = None,
    ):
        """Initialize the scheduler.
        
        Args:
            database: Database instance
            discovery_orchestrator: Discovery orchestrator
            classification_pipeline: Classification pipeline
            config: Scheduler configuration
        """
        self.database = database
        self.discovery_orchestrator = discovery_orchestrator
        self.classification_pipeline = classification_pipeline
        self.config = config or {}
        
        # Task queues (in production, use Redis or similar)
        self.task_queues: Dict[TaskType, asyncio.PriorityQueue] = {
            TaskType.DISCOVERY: asyncio.PriorityQueue(),
            TaskType.CLASSIFICATION: asyncio.PriorityQueue(),
            TaskType.MAINTENANCE: asyncio.PriorityQueue(),
        }
        
        # Worker tasks
        self.workers: List[asyncio.Task] = []
        self.running = False
        
        # Statistics
        self.stats = {
            'tasks_completed': 0,
            'tasks_failed': 0,
            'tasks_queued': 0,
            'workers_active': 0,
        }
    
    async def start(self, num_workers: int = 3):
        """Start the scheduler with a given number of workers.
        
        Args:
            num_workers: Number of worker tasks to start
        """
        if self.running:
            logger.warning("Scheduler already running")
            return
        
        self.running = True
        logger.info(f"Starting scheduler with {num_workers} workers")
        
        # Start workers
        for i in range(num_workers):
            worker = asyncio.create_task(self._worker_loop(f"worker-{i}"))
            self.workers.append(worker)
        
        # Start periodic task generation
        asyncio.create_task(self._periodic_task_generator())
        
        logger.info("Scheduler started")
    
    async def stop(self):
        """Stop the scheduler and all workers."""
        if not self.running:
            return
        
        self.running = False
        logger.info("Stopping scheduler...")
        
        # Cancel all workers
        for worker in self.workers:
            if not worker.done():
                worker.cancel()
        
        # Wait for workers to finish
        if self.workers:
            await asyncio.gather(*self.workers, return_exceptions=True)
        
        self.workers.clear()
        logger.info("Scheduler stopped")
    
    async def _worker_loop(self, worker_id: str):
        """Worker loop that processes tasks from queues.
        
        Args:
            worker_id: Identifier for the worker
        """
        logger.debug(f"Worker {worker_id} started")
        
        while self.running:
            try:
                # Get the highest priority task from any queue
                # We'll check queues in order of priority: CRITICAL tasks first
                task = None
                for queue in self.task_queues.values():
                    if not queue.empty():
                        task = await queue.get()
                        break
                
                if task is None:
                    # No tasks, wait a bit
                    await asyncio.sleep(1)
                    continue
                
                # Process the task
                self.stats['workers_active'] += 1
                await self._process_task(task)
                self.stats['workers_active'] -= 1
                self.stats['tasks_completed'] += 1
                
                # Mark task as done
                queue.task_done()
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Worker {worker_id} error: {e}")
                self.stats['tasks_failed'] += 1
        
        logger.debug(f"Worker {worker_id} stopped")
    
    async def _process_task(self, task: Dict[str, Any]):
        """Process a single task.
        
        Args:
            task: Task dictionary
        """
        task_type = task.get('type')
        
        try:
            if task_type == TaskType.DISCOVERY.value:
                await self._process_discovery_task(task)
            elif task_type == TaskType.CLASSIFICATION.value:
                await self._process_classification_task(task)
            elif task_type == TaskType.MAINTENANCE.value:
                await self._process_maintenance_task(task)
            else:
                logger.error(f"Unknown task type: {task_type}")
        
        except Exception as e:
            logger.error(f"Task processing failed: {e}")
            # Optionally, retry the task
            if task.get('retry_count', 0) < 3:
                task['retry_count'] = task.get('retry_count', 0) + 1
                await self.schedule_task(task)
    
    async def _process_discovery_task(self, task: Dict[str, Any]):
        """Process a discovery task.
        
        Args:
            task: Discovery task
        """
        logger.info("Processing discovery task")
        
        # Get seed URLs from database or config
        seed_urls = task.get('seed_urls')
        if not seed_urls:
            # Get some active sites to use as seeds
            async with self.database.get_session() as session:
                repo = SiteRepository(self.database)
                sites = await repo.get_pending_sites(session, limit=20)
                seed_urls = [site.onion_address for site in sites]
        
        # Run discovery
        results = await self.discovery_orchestrator.discover(
            seed_urls=seed_urls,
            known_urls=set(),  # Will be loaded by orchestrator
        )
        
        logger.info(f"Discovery completed: {results['sites_discovered']} sites discovered")
        
        # Schedule classification for newly discovered sites
        if results['sites_discovered'] > 0:
            # We could schedule classification tasks for each new site
            # For now, we'll just log
            logger.info(f"Scheduling classification for {results['sites_discovered']} new sites")
    
    async def _process_classification_task(self, task: Dict[str, Any]):
        """Process a classification task.
        
        Args:
            task: Classification task
        """
        site_id = task.get('site_id')
        url = task.get('url')
        
        if site_id:
            # Classify a specific site from database
            logger.info(f"Processing classification task for site {site_id}")
            # TODO: Fetch site content and classify
        elif url:
            # Classify a specific URL
            logger.info(f"Processing classification task for URL {url}")
            # TODO: Fetch URL content and classify
    
    async def _process_maintenance_task(self, task: Dict[str, Any]):
        """Process a maintenance task.
        
        Args:
            task: Maintenance task
        """
        logger.info("Processing maintenance task")
        
        # Example maintenance tasks:
        # - Clean up old data
        # - Update pattern databases
        # - Backup database
        # - Rotate logs
        
        action = task.get('action')
        if action == 'cleanup':
            # Clean up old data
            async with self.database.get_session() as session:
                # Delete sites that haven't been seen in 30 days
                stmt = """
                    DELETE FROM sites 
                    WHERE last_checked < NOW() - INTERVAL '30 days'
                    AND status = 'dead'
                """
                await session.execute(stmt)
                await session.commit()
                logger.info("Cleaned up old sites")
    
    async def _periodic_task_generator(self):
        """Generate periodic tasks (discovery, maintenance, etc.)."""
        while self.running:
            try:
                # Schedule discovery task every hour
                await self.schedule_discovery_task()
                
                # Schedule maintenance task every day
                await self.schedule_maintenance_task()
                
                # Schedule classification tasks for unclassified sites
                await self.schedule_classification_tasks(limit=10)
                
                # Wait before generating more tasks
                await asyncio.sleep(3600)  # 1 hour
                
            except Exception as e:
                logger.error(f"Periodic task generator error: {e}")
                await asyncio.sleep(60)
    
    async def schedule_discovery_task(self):
        """Schedule a discovery task."""
        task = {
            'type': TaskType.DISCOVERY.value,
            'priority': TaskPriority.MEDIUM.value,
            'created_at': datetime.now().isoformat(),
            'scheduled_for': datetime.now().isoformat(),
        }
        await self.task_queues[TaskType.DISCOVERY].put((TaskPriority.MEDIUM.value, task))
        self.stats['tasks_queued'] += 1
    
    async def schedule_classification_tasks(self, limit: int = 10):
        """Schedule classification tasks for unclassified sites.
        
        Args:
            limit: Maximum number of tasks to schedule
        """
        async with self.database.get_session() as session:
            repo = SiteRepository(self.database)
            sites = await repo.get_pending_sites(session, limit=limit)
            
            for site in sites:
                task = {
                    'type': TaskType.CLASSIFICATION.value,
                    'priority': TaskPriority.MEDIUM.value,
                    'site_id': str(site.id),
                    'url': site.onion_address,
                    'created_at': datetime.now().isoformat(),
                    'scheduled_for': datetime.now().isoformat(),
                }
                await self.task_queues[TaskType.CLASSIFICATION].put((TaskPriority.MEDIUM.value, task))
                self.stats['tasks_queued'] += 1
    
    async def schedule_maintenance_task(self):
        """Schedule a maintenance task."""
        # Only schedule maintenance once per day
        now = datetime.now()
        if now.hour == 3:  # Run at 3 AM
            task = {
                'type': TaskType.MAINTENANCE.value,
                'priority': TaskPriority.LOW.value,
                'action': 'cleanup',
                'created_at': now.isoformat(),
                'scheduled_for': now.isoformat(),
            }
            await self.task_queues[TaskType.MAINTENANCE].put((TaskPriority.LOW.value, task))
            self.stats['tasks_queued'] += 1
    
    async def schedule_task(self, task: Dict[str, Any]):
        """Schedule a custom task.
        
        Args:
            task: Task dictionary
        """
        task_type = task.get('type')
        if task_type not in [t.value for t in TaskType]:
            logger.error(f"Invalid task type: {task_type}")
            return
        
        priority = task.get('priority', TaskPriority.MEDIUM.value)
        
        # Convert string task type to enum
        for t in TaskType:
            if t.value == task_type:
                await self.task_queues[t].put((priority, task))
                self.stats['tasks_queued'] += 1
                break
    
    def get_stats(self) -> Dict[str, Any]:
        """Get scheduler statistics.
        
        Returns:
            Dictionary with statistics
        """
        stats = self.stats.copy()
        stats['running'] = self.running
        stats['workers_total'] = len(self.workers)
        
        # Queue sizes
        for task_type, queue in self.task_queues.items():
            stats[f'queue_{task_type.value}_size'] = queue.qsize()
        
        return stats