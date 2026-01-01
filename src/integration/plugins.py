"""
Plugin system for integrating with other research tools.
"""

import asyncio
import json
import inspect
from typing import Dict, List, Any, Optional, Callable, Type
from dataclasses import dataclass
from abc import ABC, abstractmethod
import logging
from pathlib import Path

from src.utils.logger import get_logger

logger = get_logger(__name__)


class PluginEvent:
    """Event that plugins can subscribe to."""
    
    SITE_DISCOVERED = "site_discovered"
    SITE_CLASSIFIED = "site_classified"
    HIGH_RISK_DETECTED = "high_risk_detected"
    SAFETY_VIOLATION = "safety_violation"
    SYSTEM_METRICS = "system_metrics"
    PIPELINE_COMPLETE = "pipeline_complete"


@dataclass
class EventData:
    """Data for plugin events."""
    event_type: str
    timestamp: float
    data: Dict[str, Any]
    source: str = "arachne"


class BasePlugin(ABC):
    """Base class for all plugins."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize plugin.
        
        Args:
            config: Plugin configuration
        """
        self.config = config or {}
        self.name = self.__class__.__name__
        self.enabled = True
    
    @abstractmethod
    async def initialize(self):
        """Initialize plugin."""
        pass
    
    @abstractmethod
    async def shutdown(self):
        """Shutdown plugin."""
        pass
    
    async def handle_event(self, event: EventData):
        """Handle an event.
        
        Args:
            event: Event data
        """
        if not self.enabled:
            return
        
        try:
            await self._process_event(event)
        except Exception as e:
            logger.error(f"Plugin {self.name} error handling event: {e}")
    
    @abstractmethod
    async def _process_event(self, event: EventData):
        """Process an event (to be implemented by subclasses).
        
        Args:
            event: Event data
        """
        pass


class PluginManager:
    """Manages plugins and event distribution."""
    
    def __init__(self):
        """Initialize plugin manager."""
        self.plugins: Dict[str, BasePlugin] = {}
        self.event_handlers: Dict[str, List[BasePlugin]] = {}
        self.enabled = True
    
    def register_plugin(self, plugin: BasePlugin):
        """Register a plugin.
        
        Args:
            plugin: Plugin instance
        """
        self.plugins[plugin.name] = plugin
        
        # Register for events based on methods
        for attr_name in dir(plugin):
            if attr_name.startswith('on_'):
                event_type = attr_name[3:]  # Remove 'on_'
                if event_type not in self.event_handlers:
                    self.event_handlers[event_type] = []
                self.event_handlers[event_type].append(plugin)
        
        logger.info(f"Registered plugin: {plugin.name}")
    
    async def initialize_all(self):
        """Initialize all plugins."""
        for plugin in self.plugins.values():
            try:
                await plugin.initialize()
                logger.info(f"Initialized plugin: {plugin.name}")
            except Exception as e:
                logger.error(f"Failed to initialize plugin {plugin.name}: {e}")
                plugin.enabled = False
    
    async def shutdown_all(self):
        """Shutdown all plugins."""
        for plugin in self.plugins.values():
            if plugin.enabled:
                try:
                    await plugin.shutdown()
                    logger.info(f"Shutdown plugin: {plugin.name}")
                except Exception as e:
                    logger.error(f"Failed to shutdown plugin {plugin.name}: {e}")
    
    async def emit_event(self, event: EventData):
        """Emit an event to all interested plugins.
        
        Args:
            event: Event data
        """
        if not self.enabled:
            return
        
        handlers = self.event_handlers.get(event.event_type, [])
        
        if handlers:
            # Dispatch to all handlers concurrently
            tasks = [plugin.handle_event(event) for plugin in handlers]
            await asyncio.gather(*tasks, return_exceptions=True)
            
            logger.debug(f"Dispatched event {event.event_type} to {len(handlers)} plugins")
    
    def get_plugin(self, name: str) -> Optional[BasePlugin]:
        """Get plugin by name.
        
        Args:
            name: Plugin name
            
        Returns:
            Plugin instance or None
        """
        return self.plugins.get(name)
    
    def list_plugins(self) -> List[Dict[str, Any]]:
        """List all plugins.
        
        Returns:
            List of plugin information
        """
        return [
            {
                'name': plugin.name,
                'enabled': plugin.enabled,
                'config': plugin.config,
            }
            for plugin in self.plugins.values()
        ]


# ==================== Built-in Plugins ====================

class ElasticsearchPlugin(BasePlugin):
    """Plugin for Elasticsearch integration."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        
        self.hosts = self.config.get('hosts', ['localhost:9200'])
        self.index_prefix = self.config.get('index_prefix', 'arachne')
        self.client = None
    
    async def initialize(self):
        """Initialize Elasticsearch client."""
        try:
            from elasticsearch import AsyncElasticsearch
            
            self.client = AsyncElasticsearch(
                hosts=self.hosts,
                timeout=30,
                max_retries=3,
                retry_on_timeout=True,
            )
            
            # Test connection
            await self.client.ping()
            logger.info(f"Elasticsearch plugin connected to {self.hosts}")
            
        except ImportError:
            logger.error("elasticsearch package not installed. Install with: pip install elasticsearch")
            self.enabled = False
        except Exception as e:
            logger.error(f"Failed to connect to Elasticsearch: {e}")
            self.enabled = False
    
    async def shutdown(self):
        """Shutdown Elasticsearch client."""
        if self.client:
            await self.client.close()
    
    async def on_site_classified(self, event: EventData):
        """Index classified sites in Elasticsearch."""
        if not self.client or not self.enabled:
            return
        
        data = event.data
        site_id = data.get('site_id')
        
        if not site_id:
            return
        
        # Prepare document
        doc = {
            'site_id': site_id,
            'onion_address': data.get('onion_address'),
            'category': data.get('category'),
            'risk_level': data.get('risk_level'),
            'timestamp': event.timestamp,
            'metadata': data.get('metadata', {}),
        }
        
        try:
            index_name = f"{self.index_prefix}-sites"
            await self.client.index(
                index=index_name,
                id=site_id,
                document=doc
            )
            logger.debug(f"Indexed site {site_id} in Elasticsearch")
        except Exception as e:
            logger.error(f"Failed to index site in Elasticsearch: {e}")


class SlackNotificationPlugin(BasePlugin):
    """Plugin for Slack notifications."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        
        self.webhook_url = self.config.get('webhook_url')
        self.channel = self.config.get('channel', '#arachne-alerts')
        self.min_risk_level = self.config.get('min_risk_level', 'high')
    
    async def initialize(self):
        """Initialize Slack plugin."""
        if not self.webhook_url:
            logger.warning("Slack webhook URL not configured")
            self.enabled = False
    
    async def shutdown(self):
        """Shutdown Slack plugin."""
        pass
    
    async def on_high_risk_detected(self, event: EventData):
        """Send Slack notification for high-risk sites."""
        if not self.enabled:
            return
        
        data = event.data
        risk_level = data.get('risk_level', '').lower()
        
        # Check risk level threshold
        risk_levels = ['low', 'medium', 'high', 'critical']
        min_index = risk_levels.index(self.min_risk_level.lower())
        current_index = risk_levels.index(risk_level) if risk_level in risk_levels else -1
        
        if current_index < min_index:
            return
        
        # Prepare notification
        message = {
            "channel": self.channel,
            "text": f"⚠️ High-risk site detected",
            "blocks": [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": "⚠️ High-risk site detected"
                    }
                },
                {
                    "type": "section",
                    "fields": [
                        {
                            "type": "mrkdwn",
                            "text": f"*Site:*\n{data.get('onion_address', 'Unknown')}"
                        },
                        {
                            "type": "mrkdwn",
                            "text": f"*Risk Level:*\n{risk_level.upper()}"
                        },
                        {
                            "type": "mrkdwn",
                            "text": f"*Category:*\n{data.get('category', 'Unknown')}"
                        },
                        {
                            "type": "mrkdwn",
                            "text": f"*Score:*\n{data.get('risk_score', 0):.2f}"
                        }
                    ]
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*Factors:* {', '.join(data.get('risk_factors', []))[:100]}..."
                    }
                }
            ]
        }
        
        try:
            import aiohttp
            
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    self.webhook_url,
                    json=message,
                    timeout=10
                ) as response:
                    if response.status != 200:
                        logger.error(f"Slack notification failed: {response.status}")
        
        except Exception as e:
            logger.error(f"Failed to send Slack notification: {e}")


class MaltegoExportPlugin(BasePlugin):
    """Plugin for Maltego export."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        
        self.export_dir = Path(self.config.get('export_dir', 'exports/maltego'))
        self.export_format = self.config.get('format', 'csv')
        self.export_dir.mkdir(parents=True, exist_ok=True)
    
    async def initialize(self):
        """Initialize Maltego plugin."""
        logger.info(f"Maltego export plugin initialized: {self.export_dir}")
    
    async def shutdown(self):
        """Shutdown Maltego plugin."""
        pass
    
    async def on_site_classified(self, event: EventData):
        """Export site data for Maltego."""
        if not self.enabled:
            return
        
        data = event.data
        
        # Prepare Maltego entities
        entities = []
        
        # Site entity
        site_entity = {
            'Type': 'arachne.OnionSite',
            'Value': data.get('onion_address'),
            'Weight': int(data.get('risk_score', 0) * 100),
            'Properties': {
                'category': data.get('category'),
                'risk_level': data.get('risk_level'),
                'first_seen': data.get('first_seen'),
                'last_checked': data.get('last_checked'),
            }
        }
        entities.append(site_entity)
        
        # Links to other sites (if discovered from this site)
        discovered_links = data.get('discovered_links', [])
        for link in discovered_links[:10]:  # Limit to first 10
            link_entity = {
                'Type': 'arachne.Link',
                'Value': link,
                'Properties': {
                    'source': data.get('onion_address'),
                    'discovery_method': data.get('discovery_method', 'crawl'),
                }
            }
            entities.append(link_entity)
        
        # Export to file
        await self._export_entities(entities)
    
    async def _export_entities(self, entities: List[Dict[str, Any]]):
        """Export entities to file.
        
        Args:
            entities: List of entities to export
        """
        timestamp = int(time.time())
        filename = self.export_dir / f"maltego_export_{timestamp}.{self.export_format}"
        
        if self.export_format == 'csv':
            await self._export_csv(entities, filename)
        elif self.export_format == 'json':
            await self._export_json(entities, filename)
        elif self.export_format == 'mtg':
            await self._export_mtg(entities, filename)
        
        logger.debug(f"Exported {len(entities)} entities to {filename}")
    
    async def _export_csv(self, entities: List[Dict[str, Any]], filename: Path):
        """Export to CSV format.
        
        Args:
            entities: Entities to export
            filename: Output filename
        """
        import csv
        
        # Flatten entities for CSV
        rows = []
        for entity in entities:
            row = {
                'type': entity['Type'],
                'value': entity['Value'],
                'weight': entity.get('Weight', 0),
            }
            row.update(entity.get('Properties', {}))
            rows.append(row)
        
        if rows:
            fieldnames = rows[0].keys()
            with open(filename, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(rows)
    
    async def _export_json(self, entities: List[Dict[str, Any]], filename: Path):
        """Export to JSON format.
        
        Args:
            entities: Entities to export
            filename: Output filename
        """
        with open(filename, 'w') as f:
            json.dump(entities, f, indent=2)
    
    async def _export_mtg(self, entities: List[Dict[str, Any]], filename: Path):
        """Export to Maltego format.
        
        Args:
            entities: Entities to export
            filename: Output filename
        """
        # Simple Maltego format
        lines = []
        for entity in entities:
            lines.append(f"Entity: {entity['Type']}")
            lines.append(f"Value: {entity['Value']}")
            if 'Weight' in entity:
                lines.append(f"Weight: {entity['Weight']}")
            
            for key, value in entity.get('Properties', {}).items():
                lines.append(f"Property.{key}: {value}")
            
            lines.append("")  # Empty line between entities
        
        with open(filename, 'w') as f:
            f.write('\n'.join(lines))


class ThreatIntelPlugin(BasePlugin):
    """Plugin for threat intelligence integration."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        
        self.intel_sources = self.config.get('sources', [])
        self.api_keys = self.config.get('api_keys', {})
        
        # Cache for intelligence data
        self.intel_cache: Dict[str, Dict[str, Any]] = {}
    
    async def initialize(self):
        """Initialize threat intelligence plugin."""
        logger.info(f"Threat intelligence plugin initialized with {len(self.intel_sources)} sources")
    
    async def shutdown(self):
        """Shutdown threat intelligence plugin."""
        pass
    
    async def on_site_discovered(self, event: EventData):
        """Enrich site with threat intelligence.
        
        Args:
            event: Discovery event
        """
        if not self.enabled:
            return
        
        data = event.data
        onion_address = data.get('onion_address')
        
        if not onion_address:
            return
        
        # Check cache first
        if onion_address in self.intel_cache:
            intel_data = self.intel_cache[onion_address]
        else:
            # Query intelligence sources
            intel_data = await self._query_intel_sources(onion_address)
            self.intel_cache[onion_address] = intel_data
        
        # Add intelligence to event data
        if intel_data:
            data['threat_intel'] = intel_data
            logger.debug(f"Added threat intelligence for {onion_address}")
    
    async def _query_intel_sources(self, onion_address: str) -> Dict[str, Any]:
        """Query threat intelligence sources.
        
        Args:
            onion_address: Onion address to query
            
        Returns:
            Threat intelligence data
        """
        intel_data = {}
        
        for source in self.intel_sources:
            try:
                if source == 'virustotal':
                    result = await self._query_virustotal(onion_address)
                    if result:
                        intel_data['virustotal'] = result
                
                elif source == 'abuseipdb':
                    result = await self._query_abuseipdb(onion_address)
                    if result:
                        intel_data['abuseipdb'] = result
                
                elif source == 'alienvault':
                    result = await self._query_alienvault(onion_address)
                    if result:
                        intel_data['alienvault'] = result
                
            except Exception as e:
                logger.error(f"Failed to query {source} for {onion_address}: {e}")
        
        return intel_data
    
    async def _query_virustotal(self, onion_address: str) -> Optional[Dict[str, Any]]:
        """Query VirusTotal.
        
        Args:
            onion_address: Onion address
            
        Returns:
            VirusTotal data or None
        """
        api_key = self.api_keys.get('virustotal')
        if not api_key:
            return None
        
        # VirusTotal doesn't directly support onion addresses
        # We could hash the address and search
        import hashlib
        
        hash_value = hashlib.sha256(onion_address.encode()).hexdigest()
        
        try:
            import aiohttp
            
            headers = {
                'x-apikey': api_key,
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f'https://www.virustotal.com/api/v3/search?query={hash_value}',
                    headers=headers,
                    timeout=10
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        return data
                    else:
                        logger.debug(f"VirusTotal query failed: {response.status}")
        
        except Exception as e:
            logger.debug(f"VirusTotal query error: {e}")
        
        return None
    
    async def _query_abuseipdb(self, onion_address: str) -> Optional[Dict[str, Any]]:
        """Query AbuseIPDB.
        
        Args:
            onion_address: Onion address
            
        Returns:
            AbuseIPDB data or None
        """
        api_key = self.api_keys.get('abuseipdb')
        if not api_key:
            return None
        
        # AbuseIPDB doesn't support onion addresses directly
        # We could check associated IPs if we have them
        return None
    
    async def _query_alienvault(self, onion_address: str) -> Optional[Dict[str, Any]]:
        """Query AlienVault OTX.
        
        Args:
            onion_address: Onion address
            
        Returns:
            AlienVault data or None
        """
        api_key = self.api_keys.get('alienvault')
        if not api_key:
            return None
        
        try:
            import aiohttp
            
            headers = {
                'X-OTX-API-KEY': api_key,
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f'https://otx.alienvault.com/api/v1/indicators/domain/{onion_address}',
                    headers=headers,
                    timeout=10
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        return data
                    else:
                        logger.debug(f"AlienVault query failed: {response.status}")
        
        except Exception as e:
            logger.debug(f"AlienVault query error: {e}")
        
        return None


class PluginLoader:
    """Loads plugins from configuration."""
    
    @staticmethod
    def load_from_config(config: Dict[str, Any]) -> PluginManager:
        """Load plugins from configuration.
        
        Args:
            config: Plugin configuration
            
        Returns:
            Plugin manager with loaded plugins
        """
        manager = PluginManager()
        
        # Built-in plugins
        builtin_plugins = {
            'elasticsearch': ElasticsearchPlugin,
            'slack': SlackNotificationPlugin,
            'maltego': MaltegoExportPlugin,
            'threat_intel': ThreatIntelPlugin,
        }
        
        # Load each plugin from config
        for plugin_name, plugin_config in config.items():
            if plugin_name in builtin_plugins:
                plugin_class = builtin_plugins[plugin_name]
                
                try:
                    plugin = plugin_class(plugin_config)
                    manager.register_plugin(plugin)
                except Exception as e:
                    logger.error(f"Failed to load plugin {plugin_name}: {e}")
            else:
                logger.warning(f"Unknown plugin: {plugin_name}")
        
        return manager