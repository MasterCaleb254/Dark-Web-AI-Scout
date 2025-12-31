"""
Health monitoring for Arachne system.
"""

import asyncio
import psutil
from typing import Dict, List, Optional, Any
from datetime import datetime
import logging

from src.utils.logger import get_logger
from src.storage.database import Database

logger = get_logger(__name__)


class HealthStatus(Enum):
    """Health status levels."""
    HEALTHY = "healthy"
    WARNING = "warning"
    CRITICAL = "critical"
    UNKNOWN = "unknown"


class HealthCheck:
    """Base class for health checks."""
    
    def __init__(self, name: str, interval: int = 60):
        """Initialize health check.
        
        Args:
            name: Name of the health check
            interval: Check interval in seconds
        """
        self.name = name
        self.interval = interval
        self.last_check: Optional[datetime] = None
        self.last_status: HealthStatus = HealthStatus.UNKNOWN
        self.last_message: Optional[str] = None
    
    async def check(self) -> Dict[str, Any]:
        """Run the health check.
        
        Returns:
            Dictionary with check results
        """
        raise NotImplementedError


class DatabaseHealthCheck(HealthCheck):
    """Check database health."""
    
    def __init__(self, database: Database, interval: int = 30):
        """Initialize database health check.
        
        Args:
            database: Database instance
            interval: Check interval in seconds
        """
        super().__init__("database", interval)
        self.database = database
    
    async def check(self) -> Dict[str, Any]:
        """Check database connection and performance.
        
        Returns:
            Dictionary with check results
        """
        self.last_check = datetime.now()
        
        try:
            # Check connection
            async with self.database.get_session() as session:
                # Simple query to check responsiveness
                result = await session.execute("SELECT 1")
                row = result.fetchone()
                
                if row and row[0] == 1:
                    self.last_status = HealthStatus.HEALTHY
                    self.last_message = "Database connection OK"
                else:
                    self.last_status = HealthStatus.CRITICAL
                    self.last_message = "Database query failed"
        
        except Exception as e:
            self.last_status = HealthStatus.CRITICAL
            self.last_message = f"Database error: {str(e)}"
        
        return {
            'name': self.name,
            'status': self.last_status.value,
            'message': self.last_message,
            'timestamp': self.last_check.isoformat(),
        }


class TorHealthCheck(HealthCheck):
    """Check Tor network health."""
    
    def __init__(self, tor_manager: Any, interval: int = 60):
        """Initialize Tor health check.
        
        Args:
            tor_manager: Tor manager instance
            interval: Check interval in seconds
        """
        super().__init__("tor", interval)
        self.tor_manager = tor_manager
    
    async def check(self) -> Dict[str, Any]:
        """Check Tor connection and circuit health.
        
        Returns:
            Dictionary with check results
        """
        self.last_check = datetime.now()
        
        try:
            # Get Tor statistics
            stats = self.tor_manager.get_stats()
            
            # Check if we have active circuits
            if stats.get('healthy_circuits', 0) > 0:
                self.last_status = HealthStatus.HEALTHY
                self.last_message = f"Tor OK ({stats['healthy_circuits']} circuits)"
            else:
                self.last_status = HealthStatus.CRITICAL
                self.last_message = "No healthy Tor circuits"
        
        except Exception as e:
            self.last_status = HealthStatus.CRITICAL
            self.last_message = f"Tor error: {str(e)}"
        
        return {
            'name': self.name,
            'status': self.last_status.value,
            'message': self.last_message,
            'timestamp': self.last_check.isoformat(),
        }


class SystemHealthCheck(HealthCheck):
    """Check system resources."""
    
    def __init__(self, interval: int = 60):
        """Initialize system health check.
        
        Args:
            interval: Check interval in seconds
        """
        super().__init__("system", interval)
        self.warning_threshold = 80.0  # 80%
        self.critical_threshold = 90.0  # 90%
    
    async def check(self) -> Dict[str, Any]:
        """Check system resource usage.
        
        Returns:
            Dictionary with check results
        """
        self.last_check = datetime.now()
        
        try:
            # CPU usage
            cpu_percent = psutil.cpu_percent(interval=1)
            
            # Memory usage
            memory = psutil.virtual_memory()
            memory_percent = memory.percent
            
            # Disk usage
            disk = psutil.disk_usage('/')
            disk_percent = disk.percent
            
            # Network
            net_io = psutil.net_io_counters()
            
            # Determine overall status
            if (cpu_percent > self.critical_threshold or 
                memory_percent > self.critical_threshold or
                disk_percent > self.critical_threshold):
                self.last_status = HealthStatus.CRITICAL
            elif (cpu_percent > self.warning_threshold or 
                  memory_percent > self.warning_threshold or
                  disk_percent > self.warning_threshold):
                self.last_status = HealthStatus.WARNING
            else:
                self.last_status = HealthStatus.HEALTHY
            
            self.last_message = (
                f"CPU: {cpu_percent:.1f}%, "
                f"Memory: {memory_percent:.1f}%, "
                f"Disk: {disk_percent:.1f}%"
            )
        
        except Exception as e:
            self.last_status = HealthStatus.CRITICAL
            self.last_message = f"System check error: {str(e)}"
        
        return {
            'name': self.name,
            'status': self.last_status.value,
            'message': self.last_message,
            'timestamp': self.last_check.isoformat(),
            'metrics': {
                'cpu_percent': cpu_percent if 'cpu_percent' in locals() else None,
                'memory_percent': memory_percent if 'memory_percent' in locals() else None,
                'disk_percent': disk_percent if 'disk_percent' in locals() else None,
                'net_bytes_sent': net_io.bytes_sent if 'net_io' in locals() else None,
                'net_bytes_recv': net_io.bytes_recv if 'net_io' in locals() else None,
            },
        }


class HealthMonitor:
    """Monitors system health and sends alerts."""
    
    def __init__(self, checks: List[HealthCheck]):
        """Initialize health monitor.
        
        Args:
            checks: List of health checks to run
        """
        self.checks = checks
        self.running = False
        self.health_history: List[Dict[str, Any]] = []
        self.max_history = 1000
        
        # Alerting
        self.alerts_enabled = True
        self.alert_history: List[Dict[str, Any]] = []
        
        # Statistics
        self.stats = {
            'checks_run': 0,
            'alerts_triggered': 0,
        }
    
    async def start(self, interval: int = 60):
        """Start health monitoring.
        
        Args:
            interval: Interval between health checks in seconds
        """
        if self.running:
            logger.warning("Health monitor already running")
            return
        
        self.running = True
        logger.info(f"Starting health monitor with {interval} second interval")
        
        while self.running:
            try:
                # Run all health checks
                for check in self.checks:
                    if check.last_check is None or (
                        (datetime.now() - check.last_check).total_seconds() >= check.interval
                    ):
                        result = await check.check()
                        self.health_history.append(result)
                        self.stats['checks_run'] += 1
                        
                        # Check if alert is needed
                        if result['status'] in ['warning', 'critical']:
                            await self._trigger_alert(result)
                
                # Trim history
                if len(self.health_history) > self.max_history:
                    self.health_history = self.health_history[-self.max_history:]
                
                # Wait for next check cycle
                await asyncio.sleep(interval)
            
            except Exception as e:
                logger.error(f"Health monitor error: {e}")
                await asyncio.sleep(interval)
    
    async def stop(self):
        """Stop health monitoring."""
        self.running = False
        logger.info("Health monitor stopped")
    
    async def _trigger_alert(self, check_result: Dict[str, Any]):
        """Trigger an alert for a health check failure.
        
        Args:
            check_result: Health check result
        """
        if not self.alerts_enabled:
            return
        
        alert = {
            'type': 'health',
            'severity': check_result['status'],
            'check': check_result['name'],
            'message': check_result['message'],
            'timestamp': datetime.now().isoformat(),
        }
        
        self.alert_history.append(alert)
        self.stats['alerts_triggered'] += 1
        
        # Log the alert
        logger.warning(f"Health alert: {check_result['name']} - {check_result['message']}")
        
        # TODO: Send alert via email, Slack, etc.
        # This would be implemented based on the deployment environment
    
    def get_health_summary(self) -> Dict[str, Any]:
        """Get current health summary.
        
        Returns:
            Dictionary with health summary
        """
        summary = {
            'overall': HealthStatus.HEALTHY.value,
            'checks': [],
            'timestamp': datetime.now().isoformat(),
        }
        
        for check in self.checks:
            check_summary = {
                'name': check.name,
                'status': check.last_status.value,
                'message': check.last_message,
                'last_check': check.last_check.isoformat() if check.last_check else None,
            }
            summary['checks'].append(check_summary)
            
            # Update overall status
            if check.last_status == HealthStatus.CRITICAL:
                summary['overall'] = HealthStatus.CRITICAL.value
            elif (check.last_status == HealthStatus.WARNING and 
                  summary['overall'] == HealthStatus.HEALTHY.value):
                summary['overall'] = HealthStatus.WARNING.value
        
        return summary
    
    def get_recent_alerts(self, limit: int = 20) -> List[Dict[str, Any]]:
        """Get recent alerts.
        
        Args:
            limit: Maximum number of alerts to return
            
        Returns:
            List of recent alerts
        """
        return self.alert_history[-limit:] if self.alert_history else []
    
    def get_stats(self) -> Dict[str, Any]:
        """Get health monitor statistics.
        
        Returns:
            Dictionary with statistics
        """
        stats = self.stats.copy()
        stats['running'] = self.running
        stats['checks_configured'] = len(self.checks)
        stats['alerts_pending'] = len(self.alert_history)
        return stats