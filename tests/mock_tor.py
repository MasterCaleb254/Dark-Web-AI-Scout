"""
Mock Tor network for testing without real Tor.
"""

import asyncio
import time
import random
from typing import Dict, List, Optional, Any, Union
from unittest.mock import Mock, AsyncMock, MagicMock
from dataclasses import dataclass
from contextlib import contextmanager

import aiohttp
from aiohttp import web
from aiohttp.test_utils import AioHTTPTestCase, unittest_run_loop

from src.core.tor_manager import TorManager, Circuit, CircuitState
from src.utils.logger import get_logger, setup_logger

logger = get_logger(__name__)


class MockTorServer:
    """Mock Tor server for testing."""
    
    def __init__(self, port: int = 9050):
        self.port = port
        self.app = web.Application()
        self.runner = None
        self.site = None
        
        # Mock onion sites
        self.mock_sites: Dict[str, str] = {
            # Legitimate sites
            'http://privacy2zbidut4m4jyj3ksdqidzkw3uoip2vhvhbvwxbqux5xy5obyd.onion': '''
                <html>
                <title>Privacy Service</title>
                <body>
                <h1>Secure Email Service</h1>
                <p>Private, encrypted email service.</p>
                <a href="/about">About</a>
                <a href="http://library3fynbw5zhrhi2v6oyv3aeyv7r2okqj2mxfdisfcac3xcf7vad.onion">Library</a>
                </body>
                </html>
            ''',
            'http://library3fynbw5zhrhi2v6oyv3aeyv7r2okqj2mxfdisfcac3xcf7vad.onion': '''
                <html>
                <title>Digital Library</title>
                <body>
                <h1>Free Knowledge Library</h1>
                <p>Collection of free books and documents.</p>
                <a href="/books">Books</a>
                <a href="http://forum4fynbw5zhrhi2v6oyv3aeyv7r2okqj2mxfdisfcac3xcf7vad.onion">Forum</a>
                </body>
                </html>
            ''',
            'http://forum4fynbw5zhrhi2v6oyv3aeyv7r2okqj2mxfdisfcac3xcf7vad.onion': '''
                <html>
                <title>Discussion Forum</title>
                <body>
                <h1>Community Forum</h1>
                <p>Discuss various topics.</p>
                <a href="/register">Register</a>
                <a href="/login">Login</a>
                <a href="http://market4fynbw5zhrhi2v6oyv3aeyv7r2okqj2mxfdisfcac3xcf7vad.onion">Market</a>
                </body>
                </html>
            ''',
            'http://market4fynbw5zhrhi2v6oyv3aeyv7r2okqj2mxfdisfcac3xcf7vad.onion': '''
                <html>
                <title>Marketplace</title>
                <body>
                <h1>Digital Marketplace</h1>
                <p>Buy and sell digital goods.</p>
                <span class="price">Price: 0.5 BTC</span>
                <form action="/cart"><button>Add to Cart</button></form>
                </body>
                </html>
            ''',
            
            # Suspicious sites
            'http://suspicious1.onion': '''
                <html>
                <body>
                <h1>Free Bitcoin Generator!</h1>
                <p>Click here to get free bitcoin! 100% working!</p>
                <form action="/login">Enter your wallet address:</form>
                </body>
                </html>
            ''',
            
            # Error testing
            'http://timeout.onion': 'TIMEOUT',
            'http://error.onion': 'ERROR_500',
            'http://redirect.onion': 'REDIRECT',
        }
        
        self._setup_routes()
    
    def _setup_routes(self):
        """Setup HTTP routes for mock sites."""
        
        async def handle_request(request):
            url = str(request.url)
            
            # Simulate network delay
            await asyncio.sleep(random.uniform(0.1, 0.5))
            
            # Check if site exists
            for mock_url, content in self.mock_sites.items():
                if url.startswith(mock_url):
                    if content == 'TIMEOUT':
                        await asyncio.sleep(10)  # Simulate timeout
                        raise asyncio.TimeoutError()
                    elif content == 'ERROR_500':
                        return web.Response(status=500, text='Internal Server Error')
                    elif content == 'REDIRECT':
                        raise web.HTTPFound('http://privacy2zbidut4m4jyj3ksdqidzkw3uoip2vhvhbvwxbqux5xy5obyd.onion')
                    else:
                        return web.Response(text=content, content_type='text/html')
            
            # Site not found
            return web.Response(status=404, text='Site not found')
        
        # Add catch-all route
        self.app.router.add_route('*', '/{path:.*}', handle_request)
    
    async def start(self):
        """Start mock server."""
        self.runner = web.AppRunner(self.app)
        await self.runner.setup()
        self.site = web.TCPSite(self.runner, '127.0.0.1', self.port)
        await self.site.start()
        
        logger.info(f"Mock Tor server started on port {self.port}")
    
    async def stop(self):
        """Stop mock server."""
        if self.runner:
            await self.runner.cleanup()
            logger.info("Mock Tor server stopped")


class MockTorManager(TorManager):
    """Mock Tor manager for testing."""
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        
        # Override controller with mock
        self.controller = MagicMock()
        
        # Mock circuit creation
        self._mock_circuits = []
        self._circuit_counter = 0
        
        # Mock stats
        self.mock_stats = {
            'circuits_created': 0,
            'requests_made': 0,
            'errors': 0,
        }
    
    def start(self):
        """Mock start - doesn't actually start Tor."""
        logger.info("Mock Tor manager started")
        
        # Create initial mock circuits
        for i in range(3):
            circuit_id = f"mock-circuit-{i}"
            circuit = Circuit(
                id=circuit_id,
                state=CircuitState.FRESH,
                created_at=time.time(),
                entry_node=f"entry-{i}",
                exit_node=f"exit-{i}",
            )
            self.circuits[circuit_id] = circuit
            self.active_circuits.append(circuit_id)
        
        self.mock_stats['circuits_created'] = 3
    
    def _create_circuit(self) -> Optional[str]:
        """Create a mock circuit."""
        self._circuit_counter += 1
        circuit_id = f"mock-circuit-{self._circuit_counter}"
        
        circuit = Circuit(
            id=circuit_id,
            state=CircuitState.FRESH,
            created_at=time.time(),
            entry_node=f"entry-{self._circuit_counter}",
            exit_node=f"exit-{self._circuit_counter}",
        )
        
        self.circuits[circuit_id] = circuit
        self.active_circuits.append(circuit_id)
        self._mock_circuits.append(circuit_id)
        
        self.mock_stats['circuits_created'] += 1
        return circuit_id
    
    @contextmanager
    def get_http_session(self, circuit: Optional[Circuit] = None):
        """Get mock HTTP session."""
        if not circuit:
            circuit = self.get_circuit()
        
        # Create mock session
        session = Mock()
        
        # Mock response based on URL
        def mock_get(url, *args, **kwargs):
            response = Mock()
            
            # Check mock sites
            mock_server = getattr(self, '_mock_server', None)
            if mock_server and mock_server.mock_sites:
                for mock_url, content in mock_server.mock_sites.items():
                    if url.startswith(mock_url):
                        if content == 'TIMEOUT':
                            raise Exception("Connection timeout")
                        elif content == 'ERROR_500':
                            response.status_code = 500
                            response.text = 'Internal Server Error'
                        else:
                            response.status_code = 200
                            response.text = content
                            response.headers = {'Content-Type': 'text/html'}
                        break
                else:
                    response.status_code = 404
                    response.text = 'Not Found'
            else:
                # Default response
                response.status_code = 200
                response.text = f'Mock response for {url}'
                response.headers = {'Content-Type': 'text/html'}
            
            response.history = []
            response.url = url
            
            self.mock_stats['requests_made'] += 1
            return response
        
        session.get = mock_get
        session.post = mock_get  # Same for POST
        session.timeout = 30
        
        yield session


@dataclass
class TestDataGenerator:
    """Generates test data for dark web simulations."""
    
    @staticmethod
    def generate_forum_page(title: str = "Test Forum") -> str:
        """Generate a forum page."""
        return f'''
        <html>
        <head><title>{title}</title></head>
        <body>
        <div class="forum-header">
            <h1>{title}</h1>
            <nav>
                <a href="/forum">Forum Home</a>
                <a href="/categories">Categories</a>
                <a href="/members">Members</a>
            </nav>
        </div>
        <div class="thread-list">
            <div class="thread">
                <h3><a href="/thread/1">Discussion about privacy tools</a></h3>
                <p>Posted by <a href="/user/johndoe">johndoe</a> • 5 hours ago</p>
            </div>
            <div class="thread">
                <h3><a href="/thread/2">Best practices for OpSec</a></h3>
                <p>Posted by <a href="/user/alice">alice</a> • 1 day ago</p>
            </div>
        </div>
        <form action="/login" method="post">
            <input type="text" name="username" placeholder="Username">
            <input type="password" name="password" placeholder="Password">
            <button type="submit">Login</button>
        </form>
        </body>
        </html>
        '''
    
    @staticmethod
    def generate_market_page(title: str = "Digital Market") -> str:
        """Generate a marketplace page."""
        return f'''
        <html>
        <head><title>{title}</title></head>
        <body>
        <div class="market-header">
            <h1>{title}</h1>
            <div class="cart">Cart: 0 items</div>
        </div>
        <div class="product-list">
            <div class="product">
                <h3>VPN Service - 1 Year</h3>
                <p class="price">Price: 0.5 BTC</p>
                <p>Secure VPN with no logs policy</p>
                <form action="/cart/add/1">
                    <button>Add to Cart</button>
                </form>
            </div>
            <div class="product">
                <h3>Encrypted Email</h3>
                <p class="price">Price: 0.2 BTC/month</p>
                <p>Private email with PGP encryption</p>
                <form action="/cart/add/2">
                    <button>Add to Cart</button>
                </form>
            </div>
        </div>
        <div class="payment-info">
            <p>Accepted: Bitcoin, Monero</p>
            <p>Wallet: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa</p>
        </div>
        </body>
        </html>
        '''
    
    @staticmethod
    def generate_scam_page() -> str:
        """Generate a scam page."""
        return '''
        <html>
        <body style="background-color: #ffcccc;">
        <h1>⚠️ URGENT: Your Bitcoin Wallet Compromised!</h1>
        <p>We detected suspicious activity on your wallet. To secure your funds:</p>
        <ol>
            <li>Send 0.1 BTC to this address for verification: 1ScamAddress123456789</li>
            <li>We will return 0.5 BTC after verification</li>
            <li>This is a LIMITED TIME OFFER!</li>
        </ol>
        <p style="color: red; font-weight: bold;">CLICK HERE NOW TO SECURE YOUR FUNDS!</p>
        <form action="/steal_bitcoin">
            <input type="text" placeholder="Enter your private key">
            <button>VERIFY NOW</button>
        </form>
        <p style="font-size: 10px;">100% legitimate • Trusted by millions • No scam</p>
        </body>
        </html>
        '''
    
    @staticmethod
    def generate_honeypot_page() -> str:
        """Generate a honeypot page."""
        return '''
        <html>
        <body>
        <h1>🔐 Restricted Access</h1>
        <p>This area requires authentication.</p>
        <form action="/captcha">
            <div class="captcha">
                <img src="/captcha.jpg" alt="CAPTCHA">
                <input type="text" placeholder="Enter CAPTCHA">
            </div>
            <div>
                <label>Username:</label>
                <input type="text" name="username">
            </div>
            <div>
                <label>Password:</label>
                <input type="password" name="password">
            </div>
            <div>
                <label>Email:</label>
                <input type="email" name="email">
            </div>
            <div>
                <label>Phone Number:</label>
                <input type="tel" name="phone">
            </div>
            <button type="submit">Login</button>
        </form>
        <p style="font-size: 12px; color: #666;">
            By logging in, you agree to our terms and conditions.
            All activity is logged for security purposes.
        </p>
        </body>
        </html>
        '''
    
    @staticmethod
    def generate_library_page() -> str:
        """Generate a library page."""
        return '''
        <html>
        <head><title>Digital Library</title></head>
        <body>
        <h1>📚 Free Knowledge Library</h1>
        <p>Collection of books, papers, and documents.</p>
        
        <div class="category">
            <h2>Computer Science</h2>
            <ul>
                <li><a href="/books/crypto.pdf">Applied Cryptography</a> (PDF, 2.3MB)</li>
                <li><a href="/books/networking.epub">Computer Networks</a> (EPUB, 1.8MB)</li>
            </ul>
        </div>
        
        <div class="category">
            <h2>Mathematics</h2>
            <ul>
                <li><a href="/books/calculus.pdf">Calculus Made Easy</a> (PDF, 4.1MB)</li>
                <li><a href="/books/statistics.djvu">Statistics for Engineers</a> (DJVU, 3.2MB)</li>
            </ul>
        </div>
        
        <div class="search">
            <form action="/search">
                <input type="text" name="q" placeholder="Search library...">
                <button type="submit">Search</button>
            </form>
        </div>
        
        <p>Total books: 1,234 | Last updated: 2024-01-15</p>
        </body>
        </html>
        '''


class TorTestCase(AioHTTPTestCase):
    """Base test case with Tor mocking."""
    
    async def get_application(self):
        """Get aiohttp application."""
        mock_server = MockTorServer(port=0)  # Random port
        return mock_server.app
    
    async def setUpAsync(self):
        """Async setup."""
        await super().setUpAsync()
        
        # Create mock Tor manager
        self.tor_manager = MockTorManager()
        self.tor_manager.start()
        
        # Store server reference
        self.mock_server = MockTorServer()
        self.tor_manager._mock_server = self.mock_server
    
    async def tearDownAsync(self):
        """Async teardown."""
        if hasattr(self.tor_manager, '_mock_server'):
            delattr(self.tor_manager, '_mock_server')
        await super().tearDownAsync()