"""
Configuration management for Arachne.
"""

import os
import yaml
from typing import Dict, Any, Optional
from pathlib import Path
from pydantic import BaseSettings, Field, validator


class TorConfig(BaseSettings):
    """Tor configuration."""
    socks_port: int = Field(9050, env="TOR_SOCKS_PORT")
    control_port: int = Field(9051, env="TOR_CONTROL_PORT")
    control_password: Optional[str] = Field(None, env="TOR_PASSWORD")
    circuit_count: int = Field(10, env="TOR_CIRCUIT_COUNT")
    circuit_lifetime_minutes: int = Field(10, env="TOR_CIRCUIT_LIFETIME")
    max_requests_per_circuit: int = Field(100, env="TOR_MAX_REQUESTS")
    entry_guards: int = Field(3, env="TOR_ENTRY_GUARDS")


class DiscoveryConfig(BaseSettings):
    """Discovery configuration."""
    max_depth: int = Field(3, env="DISCOVERY_MAX_DEPTH")
    max_pages_per_site: int = Field(50, env="DISCOVERY_MAX_PAGES")
    concurrent_requests: int = Field(5, env="DISCOVERY_CONCURRENT")
    request_delay_min_ms: int = Field(1000, env="DISCOVERY_DELAY_MIN")
    request_delay_max_ms: int = Field(5000, env="DISCOVERY_DELAY_MAX")
    user_agents_file: str = Field("configs/user_agents.txt", env="USER_AGENTS_FILE")
    """Main configuration."""
    version: str = "0.1.0"
    log_level: str = Field("INFO", env="LOG_LEVEL")
    metrics_port: int = Field(9090, env="METRICS_PORT")
    
    tor: TorConfig = TorConfig()
    discovery: DiscoveryConfig = DiscoveryConfig()
    safety: SafetyConfig = SafetyConfig()
    database: DatabaseConfig = DatabaseConfig()
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False


def load_config(config_path: Optional[str] = None) -> Config:
    """Load configuration from YAML file and environment."""
    config_dict = {}
    
    # Load from YAML if provided
    if config_path and Path(config_path).exists():
        with open(config_path, 'r') as f:
            config_dict = yaml.safe_load(f)
    
    # Load from environment
    return Config(**config_dict)


def save_config(config: Config, config_path: str) -> None:
    """Save configuration to YAML file."""
    config_dict = config.dict(exclude={'database'})  # Don't save passwords
    with open(config_path, 'w') as f:
        yaml.dump(config_dict, f, default_flow_style=False)
