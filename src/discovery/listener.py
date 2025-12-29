"""
Social listener - monitors social channels for onion addresses.
"""

import asyncio
import re
import time
from typing import List, Set, Dict, Any, Optional, Callable
from datetime import datetime, timedelta
import logging

from src.discovery.harvester import OnionHarvester
from src.utils.logger import get_logger

logger = get_logger(__name__)


class SocialListener:
    """Listens to social channels for onion address mentions."""
    
    def __init__(
        self,
        harvester: Optional[OnionHarvester] = None,
        check_interval: int = 300,  # 5 minutes
    ):
        """Initialize social listener.
        
        Args:
            harvester: Onion harvester instance
            check_interval: Interval between checks in seconds
        """
        self.harvester = harvester or OnionHarvester()
        self.check_interval = check_interval
        
        # Track what we've already seen
        self.seen_mentions: Set[str] = set()
        self.last_check_time: Dict[str, datetime] = {}
        
        # Statistics
        self.stats = {
            'total_mentions': 0,
            'unique_onions': 0,
            'channels_monitored': 0,
            'last_update': None,
        }
    
    async def monitor_telegram(
        self,
        channel_ids: List[str],
        api_id: Optional[str] = None,
        api_hash: Optional[str] = None,
        callback: Optional[Callable[[str, Set[str]], None]] = None,
    ) -> Set[str]:
        """Monitor Telegram channels for onion addresses.
        
        Args:
            channel_ids: List of channel IDs/usernames
            api_id: Telegram API ID
            api_hash: Telegram API hash
            callback: Callback function for new mentions
            
        Returns:
            Set of discovered onion addresses
        """
        discovered = set()
        
        try:
            # Import telegram client (optional dependency)
            from telethon import TelegramClient
            from telethon.errors import SessionPasswordNeededError
            
            # Initialize client
            client = TelegramClient('arachne_session', api_id, api_hash)
            
            await client.start()
            
            for channel_id in channel_ids:
                try:
                    # Get channel
                    channel = await client.get_entity(channel_id)
                    
                    # Get recent messages
                    messages = await client.get_messages(channel, limit=100)
                    
                    for message in messages:
                        if message.text:
                            # Extract onion addresses
                            onions = self.harvester.extract_from_text(message.text)
                            
                            for onion in onions:
                                mention_id = f"{channel_id}:{message.id}:{onion}"
                                
                                if mention_id not in self.seen_mentions:
                                    self.seen_mentions.add(mention_id)
                                    discovered.add(onion)
                                    
                                    if callback:
                                        await callback(channel_id, onions)
                    
                    self.stats['channels_monitored'] += 1
                    
                except Exception as e:
                    logger.error(f"Error monitoring Telegram channel {channel_id}: {e}")
            
            await client.disconnect()
            
        except ImportError:
            logger.warning("Telethon not installed. Install with: pip install telethon")
        except Exception as e:
            logger.error(f"Error in Telegram monitoring: {e}")
        
        self._update_stats(discovered)
        return discovered
    
    async def monitor_irc(
        self,
        servers: List[Dict[str, Any]],
        channels: List[str],
        callback: Optional[Callable[[str, Set[str]], None]] = None,
    ) -> Set[str]:
        """Monitor IRC channels for onion addresses.
        
        Args:
            servers: List of server configurations
            channels: List of channels to join
            callback: Callback function for new mentions
            
        Returns:
            Set of discovered onion addresses
        """
        discovered = set()
        
        try:
            # Import IRC client (optional dependency)
            import irc.bot
            import irc.client
            
            for server_config in servers:
                server = server_config.get('host', 'irc.example.com')
                port = server_config.get('port', 6667)
                nickname = server_config.get('nickname', 'arachne_bot')
                
                try:
                    # Create IRC client
                    reactor = irc.client.Reactor()
                    
                    # Connect to server
                    connection = reactor.server().connect(
                        server, port, nickname
                    )
                    
                    # Join channels
                    for channel in channels:
                        connection.join(channel)
                    
                    # Set up message handler
                    def on_message(connection, event):
                        if event.type == 'pubmsg':
                            channel = event.target
                            message = event.arguments[0]
                            
                            # Extract onion addresses
                            onions = self.harvester.extract_from_text(message)
                            
                            for onion in onions:
                                mention_id = f"{server}:{channel}:{message[:50]}"
                                
                                if mention_id not in self.seen_mentions:
                                    self.seen_mentions.add(mention_id)
                                    discovered.add(onion)
                                    
                                    if callback:
                                        asyncio.create_task(
                                            callback(channel, onions)
                                        )
                    
                    connection.add_global_handler('pubmsg', on_message)
                    
                    # Run for a while
                    reactor.process_once(timeout=30)
                    
                except Exception as e:
                    logger.error(f"Error monitoring IRC server {server}: {e}")
        
        except ImportError:
            logger.warning("IRC library not installed. Install with: pip install irc")
        except Exception as e:
            logger.error(f"Error in IRC monitoring: {e}")
        
        self._update_stats(discovered)
        return discovered
    
    async def monitor_twitter(
        self,
        search_terms: List[str],
        bearer_token: Optional[str] = None,
        callback: Optional[Callable[[str, Set[str]], None]] = None,
    ) -> Set[str]:
        """Monitor Twitter for onion address mentions.
        
        Args:
            search_terms: List of search terms
            bearer_token: Twitter API bearer token
            callback: Callback function for new mentions
            
        Returns:
            Set of discovered onion addresses
        """
        discovered = set()
        
        try:
            # Import tweepy (optional dependency)
            import tweepy
            
            if not bearer_token:
                logger.warning("Twitter bearer token not provided")
                return discovered
            
            # Initialize client
            client = tweepy.Client(bearer_token=bearer_token)
            
            for term in search_terms:
                try:
                    # Search recent tweets
                    tweets = client.search_recent_tweets(
                        query=term,
                        max_results=100,
                        tweet_fields=['created_at', 'text']
                    )
                    
                    if tweets.data:
                        for tweet in tweets.data:
                            # Extract onion addresses
                            onions = self.harvester.extract_from_text(tweet.text)
                            
                            for onion in onions:
                                mention_id = f"twitter:{tweet.id}:{onion}"
                                
                                if mention_id not in self.seen_mentions:
                                    self.seen_mentions.add(mention_id)
                                    discovered.add(onion)
                                    
                                    if callback:
                                        await callback(term, onions)
                    
                except Exception as e:
                    logger.error(f"Error searching Twitter for {term}: {e}")
        
        except ImportError:
            logger.warning("Tweepy not installed. Install with: pip install tweepy")
        except Exception as e:
            logger.error(f"Error in Twitter monitoring: {e}")
        
        self._update_stats(discovered)
        return discovered
    
    async def monitor_clearnet_forums(
        self,
        forum_urls: List[str],
        session: Any,  # requests session or similar
        callback: Optional[Callable[[str, Set[str]], None]] = None,
    ) -> Set[str]:
        """Monitor clearnet forums for onion address mentions.
        
        Args:
            forum_urls: List of forum URLs
            session: HTTP session for making requests
            callback: Callback function for new mentions
            
        Returns:
            Set of discovered onion addresses
        """
        discovered = set()
        
        for forum_url in forum_urls:
            try:
                # Make request to forum
                response = session.get(forum_url, timeout=30)
                
                if response.status_code == 200:
                    # Extract onion addresses
                    onions = self.harvester.extract_from_html(response.text, forum_url)
                    
                    for onion in onions:
                        mention_id = f"{forum_url}:{hash(response.text[:100])}:{onion}"
                        
                        if mention_id not in self.seen_mentions:
                            self.seen_mentions.add(mention_id)
                            discovered.add(onion)
                            
                            if callback:
                                await callback(forum_url, {onion})
                
                # Rate limiting
                await asyncio.sleep(1)
                
            except Exception as e:
                logger.error(f"Error monitoring forum {forum_url}: {e}")
        
        self._update_stats(discovered)
        return discovered
    
    def _update_stats(self, new_discovered: Set[str]):
        """Update statistics.
        
        Args:
            new_discovered: Newly discovered onion addresses
        """
        self.stats['total_mentions'] += len(new_discovered)
        self.stats['unique_onions'] = len(self.seen_mentions)
        self.stats['last_update'] = datetime.now().isoformat()
    
    def get_stats(self) -> Dict[str, Any]:
        """Get listener statistics.
        
        Returns:
            Dictionary with statistics
        """
        return self.stats.copy()
    
    def clear_seen(self, older_than: Optional[timedelta] = None):
        """Clear seen mentions cache.
        
        Args:
            older_than: Clear mentions older than this timedelta
        """
        if older_than:
            # In a real implementation, we'd track timestamps
            # For now, just clear all
            pass
        
        self.seen_mentions.clear()
        logger.info("Cleared seen mentions cache")


class MultiChannelListener:
    """Listens to multiple channels simultaneously."""
    
    def __init__(
        self,
        harvester: Optional[OnionHarvester] = None,
        check_interval: int = 300,
    ):
        """Initialize multi-channel listener.
        
        Args:
            harvester: Onion harvester instance
            check_interval: Interval between checks in seconds
        """
        self.listener = SocialListener(harvester, check_interval)
        self.tasks: List[asyncio.Task] = []
        self.running = False
        
    async def start_monitoring(
        self,
        config: Dict[str, Any],
        callback: Optional[Callable[[str, str, Set[str]], None]] = None,
    ):
        """Start monitoring all configured channels.
        
        Args:
            config: Monitoring configuration
            callback: Callback for new discoveries
        """
        self.running = True
        
        # Telegram monitoring
        if 'telegram' in config:
            telegram_config = config['telegram']
            task = asyncio.create_task(
                self._monitor_telegram_continuous(telegram_config, callback)
            )
            self.tasks.append(task)
        
        # IRC monitoring
        if 'irc' in config:
            irc_config = config['irc']
            task = asyncio.create_task(
                self._monitor_irc_continuous(irc_config, callback)
            )
            self.tasks.append(task)
        
        # Twitter monitoring
        if 'twitter' in config:
            twitter_config = config['twitter']
            task = asyncio.create_task(
                self._monitor_twitter_continuous(twitter_config, callback)
            )
            self.tasks.append(task)
        
        logger.info(f"Started monitoring with {len(self.tasks)} tasks")
    
    async def _monitor_telegram_continuous(
        self,
        config: Dict[str, Any],
        callback: Optional[Callable[[str, str, Set[str]], None]] = None,
    ):
        """Monitor Telegram continuously.
        
        Args:
            config: Telegram configuration
            callback: Callback function
        """
        while self.running:
            try:
                discovered = await self.listener.monitor_telegram(
                    channel_ids=config.get('channels', []),
                    api_id=config.get('api_id'),
                    api_hash=config.get('api_hash'),
                    callback=lambda channel, onions: (
                        callback('telegram', channel, onions) if callback else None
                    ),
                )
                
                if discovered:
                    logger.info(f"Telegram monitoring found {len(discovered)} new onions")
                
            except Exception as e:
                logger.error(f"Error in continuous Telegram monitoring: {e}")
            
            await asyncio.sleep(self.listener.check_interval)
    
    async def _monitor_irc_continuous(
        self,
        config: Dict[str, Any],
        callback: Optional[Callable[[str, str, Set[str]], None]] = None,
    ):
        """Monitor IRC continuously.
        
        Args:
            config: IRC configuration
            callback: Callback function
        """
        while self.running:
            try:
                discovered = await self.listener.monitor_irc(
                    servers=config.get('servers', []),
                    channels=config.get('channels', []),
                    callback=lambda channel, onions: (
                        callback('irc', channel, onions) if callback else None
                    ),
                )
                
                if discovered:
                    logger.info(f"IRC monitoring found {len(discovered)} new onions")
                
            except Exception as e:
                logger.error(f"Error in continuous IRC monitoring: {e}")
            
            await asyncio.sleep(self.listener.check_interval)
    
    async def _monitor_twitter_continuous(
        self,
        config: Dict[str, Any],
        callback: Optional[Callable[[str, str, Set[str]], None]] = None,
    ):
        """Monitor Twitter continuously.
        
        Args:
            config: Twitter configuration
            callback: Callback function
        """
        while self.running:
            try:
                discovered = await self.listener.monitor_twitter(
                    search_terms=config.get('search_terms', []),
                    bearer_token=config.get('bearer_token'),
                    callback=lambda term, onions: (
                        callback('twitter', term, onions) if callback else None
                    ),
                )
                
                if discovered:
                    logger.info(f"Twitter monitoring found {len(discovered)} new onions")
                
            except Exception as e:
                logger.error(f"Error in continuous Twitter monitoring: {e}")
            
            await asyncio.sleep(self.listener.check_interval)
    
    async def stop_monitoring(self):
        """Stop all monitoring tasks."""
        self.running = False
        
        for task in self.tasks:
            if not task.done():
                task.cancel()
        
        # Wait for tasks to complete
        if self.tasks:
            await asyncio.gather(*self.tasks, return_exceptions=True)
        
        self.tasks.clear()
        logger.info("Stopped all monitoring tasks")
    
    def get_listener_stats(self) -> Dict[str, Any]:
        """Get listener statistics.
        
        Returns:
            Dictionary with statistics
        """
        return self.listener.get_stats()