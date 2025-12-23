"""
Tor Manager - Handles all Tor network operations with circuit isolation.
"""

import time
import random
import logging
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from enum import Enum
from contextlib import contextmanager

import stem
from stem.control import Controller
from stem.process import launch_tor_with_config
import requests
from selenium import webdriver
from selenium.webdriver.firefox.options import Options as FirefoxOptions
from selenium.webdriver.firefox.service import Service as FirefoxService

logger = logging.getLogger(__name__)


class CircuitState(Enum):
    """State of a Tor circuit."""
    FRESH = "fresh"
    ACTIVE = "active"
    DEGRADED = "degraded"
    DEAD = "dead"


@dataclass
class Circuit:
    """Represents a Tor circuit."""
    id: str
    state: CircuitState
    created_at: float
    request_count: int = 0
    last_used: Optional[float] = None
    entry_node: Optional[str] = None
    exit_node: Optional[str] = None
    
    @property
    def age(self) -> float:
        """Return circuit age in seconds."""
        return time.time() - self.created_at
    
    @property
    def is_healthy(self) -> bool:
        """Check if circuit is healthy for use."""
        if self.state == CircuitState.DEAD:
            return False
        if self.age > 600:  # 10 minutes max
            return False
        if self.request_count > 100:  # Max requests per circuit
            return False
        return True


class TorManager:
    """Manages Tor connections and circuit isolation."""
    
    def __init__(
        self,
        socks_port: int = 9050,
        control_port: int = 9051,
        control_password: Optional[str] = None,
        max_circuits: int = 10,
        circuit_lifetime: int = 600,  # 10 minutes
    ):
        self.socks_port = socks_port
        self.control_port = control_port
        self.control_password = control_password
        self.max_circuits = max_circuits
        self.circuit_lifetime = circuit_lifetime
        
        self.controller: Optional[Controller] = None
        self.circuits: Dict[str, Circuit] = {}
        self.active_circuits: List[str] = []
        
        self._tor_process = None
        self._session_cache: Dict[str, requests.Session] = {}
        
    def start(self) -> None:
        """Start Tor and establish control connection."""
        try:
            # Try to connect to existing Tor control port
            self.controller = Controller.from_port(port=self.control_port)
            
            if self.control_password:
                self.controller.authenticate(password=self.control_password)
            else:
                self.controller.authenticate()
                
            logger.info(f"Connected to existing Tor controller on port {self.control_port}")
            
        except stem.SocketError:
            # Launch new Tor process
            logger.info("Starting new Tor process...")
            
            tor_config = {
                'SocksPort': str(self.socks_port),
                'ControlPort': str(self.control_port),
                'CookieAuthentication': '1',
                'MaxCircuitDirtiness': str(self.circuit_lifetime),
                'MaxClientCircuitsPending': str(self.max_circuits),
                'UseEntryGuards': '1',
                'NumEntryGuards': '3',
            }
            
            self._tor_process = launch_tor_with_config(
                config=tor_config,
                init_msg_handler=lambda line: logger.debug(f"TOR: {line}"),
                timeout=300,
            )
            
            # Connect to newly launched Tor
            time.sleep(5)  # Give Tor time to start
            self.controller = Controller.from_port(port=self.control_port)
            self.controller.authenticate()
            
            logger.info(f"Tor process started with PID {self._tor_process.pid}")
        
        # Initialize circuits
        self._initialize_circuits()
        
    def _initialize_circuits(self) -> None:
        """Create initial set of circuits."""
        for i in range(min(3, self.max_circuits)):
            circuit_id = self._create_circuit()
            if circuit_id:
                logger.debug(f"Created initial circuit {circuit_id}")
    
    def _create_circuit(self) -> Optional[str]:
        """Create a new Tor circuit."""
        try:
            circuit_id = self.controller.new_circuit()
            
            # Get circuit info
            circuit_info = self.controller.get_circuit(circuit_id)
            
            circuit = Circuit(
                id=circuit_id,
                state=CircuitState.FRESH,
                created_at=time.time(),
                entry_node=circuit_info.path[0][0] if circuit_info.path else None,
                exit_node=circuit_info.path[-1][0] if circuit_info.path else None,
            )
            
            self.circuits[circuit_id] = circuit
            self.active_circuits.append(circuit_id)
            
            return circuit_id
            
        except stem.ControllerError as e:
            logger.error(f"Failed to create circuit: {e}")
            return None
    
    def get_circuit(self, require_fresh: bool = False) -> Optional[Circuit]:
        """Get a healthy circuit for use."""
        # Clean up dead circuits
        self._cleanup_circuits()
        
        # Find healthy circuit
        for circuit_id in self.active_circuits:
            circuit = self.circuits[circuit_id]
            
            if circuit.is_healthy:
                if require_fresh and circuit.request_count > 0:
                    continue
                    
                circuit.request_count += 1
                circuit.last_used = time.time()
                circuit.state = CircuitState.ACTIVE
                
                return circuit
        
        # Create new circuit if none available
        if len(self.active_circuits) < self.max_circuits:
            circuit_id = self._create_circuit()
            if circuit_id:
                circuit = self.circuits[circuit_id]
                circuit.request_count = 1
                circuit.last_used = time.time()
                return circuit
        
        # Recycle oldest circuit
        if self.active_circuits:
            oldest_id = min(
                self.active_circuits,
                key=lambda cid: self.circuits[cid].last_used or 0
            )
            circuit = self.circuits[oldest_id]
            circuit.request_count += 1
            circuit.last_used = time.time()
            return circuit
        
        return None
    
    def _cleanup_circuits(self) -> None:
        """Remove dead or expired circuits."""
        current_time = time.time()
        dead_circuits = []
        
        for circuit_id, circuit in list(self.circuits.items()):
            if circuit.state == CircuitState.DEAD:
                dead_circuits.append(circuit_id)
            elif circuit.age > self.circuit_lifetime:
                circuit.state = CircuitState.DEAD
                dead_circuits.append(circuit_id)
            elif circuit.request_count > 100:
                circuit.state = CircuitState.DEGRADED
        
        # Mark for removal but don't close circuits immediately
        # (they might still be in use)
        for circuit_id in dead_circuits:
            if circuit_id in self.active_circuits:
                self.active_circuits.remove(circuit_id)
    
    @contextmanager
    def get_http_session(self, circuit: Optional[Circuit] = None) -> requests.Session:
        """Get HTTP session configured for Tor with optional circuit isolation."""
        if not circuit:
            circuit = self.get_circuit()
            if not circuit:
                raise RuntimeError("No available circuits")
        
        # Create or reuse session for this circuit
        if circuit.id not in self._session_cache:
            session = requests.Session()
            
            # Configure session to use Tor
            session.proxies = {
                'http': f'socks5h://127.0.0.1:{self.socks_port}',
                'https': f'socks5h://127.0.0.1:{self.socks_port}',
            }
            
            # Add headers to mimic browser
            session.headers.update({
                'User-Agent': self._get_random_user_agent(),
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1',
            })
            
            self._session_cache[circuit.id] = session
        
        yield self._session_cache[circuit.id]
    
    def get_browser(self, circuit: Optional[Circuit] = None) -> webdriver.Firefox:
        """Get Selenium browser configured for Tor."""
        if not circuit:
            circuit = self.get_circuit()
            if not circuit:
                raise RuntimeError("No available circuits")
        
        # Configure Firefox for Tor
        options = FirefoxOptions()
        options.set_preference('network.proxy.type', 1)
        options.set_preference('network.proxy.socks', '127.0.0.1')
        options.set_preference('network.proxy.socks_port', self.socks_port)
        options.set_preference('network.proxy.socks_remote_dns', True)
        options.set_preference('javascript.enabled', True)
        options.set_preference('webdriver.log.driver', 'off')
        
        # Randomize fingerprint
        options.set_preference('general.useragent.override', self._get_random_user_agent())
        
        # Headless mode for production
        options.add_argument('--headless')
        
        service = FirefoxService(log_path='/dev/null')
        driver = webdriver.Firefox(options=options, service=service)
        
        return driver
    
    def _get_random_user_agent(self) -> str:
        """Get random user agent from pool."""
        # In production, load from file
        user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15',
            'Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/119.0',
        ]
        return random.choice(user_agents)
    
    def mark_circuit_dead(self, circuit_id: str) -> None:
        """Mark a circuit as dead (e.g., after timeout or error)."""
        if circuit_id in self.circuits:
            self.circuits[circuit_id].state = CircuitState.DEAD
            if circuit_id in self.active_circuits:
                self.active_circuits.remove(circuit_id)
    
    def rotate_all_circuits(self) -> None:
        """Rotate all circuits (emergency or scheduled)."""
        logger.warning("Rotating all circuits")
        
        # Mark all circuits as dead
        for circuit_id in list(self.circuits.keys()):
            self.mark_circuit_dead(circuit_id)
        
        # Clear session cache
        self._session_cache.clear()
        
        # Create fresh circuits
        self._initialize_circuits()
    
    def get_stats(self) -> Dict[str, Any]:
        """Get current Tor manager statistics."""
        return {
            'total_circuits': len(self.circuits),
            'active_circuits': len(self.active_circuits),
            'healthy_circuits': sum(1 for c in self.circuits.values() if c.is_healthy),
            'sessions_cached': len(self._session_cache),
        }
    
    def stop(self) -> None:
        """Stop Tor manager and cleanup."""
        logger.info("Stopping Tor manager...")
        
        # Close all browser sessions
        # (Selenium sessions should be closed by their owners)
        
        # Clear caches
        self._session_cache.clear()
        
        # Stop Tor process if we started it
        if self._tor_process:
            self._tor_process.terminate()
            self._tor_process.wait()
            logger.info("Tor process stopped")
        
        self.controller = None
        logger.info("Tor manager stopped")


# Factory function for dependency injection
def create_tor_manager(config: Dict[str, Any]) -> TorManager:
    """Create TorManager from configuration."""
    tor_config = config.get('tor', {})
    
    return TorManager(
        socks_port=tor_config.get('socks_port', 9050),
        control_port=tor_config.get('control_port', 9051),
        control_password=tor_config.get('control_password'),
        max_circuits=tor_config.get('circuit_count', 10),
        circuit_lifetime=tor_config.get('circuit_lifetime_minutes', 10) * 60,
    )
