cat > DEVELOPMENT.md << 'EOF'
# Development Setup Guide

## Initial Setup

### 1. Create Virtual Environment
```bash
# Linux/Mac
python -m venv venv
source venv/bin/activate

# Windows
python -m venv venv
venv\Scripts\activate

pip install -e ".[dev,tor]"  # Install with development and Tor dependencies

cp .env.example .env
# Edit .env with your actual configuration

# First, ensure PostgreSQL and Redis are running
sudo systemctl start postgresql
sudo systemctl start redis

# Then initialize
python scripts/init_db.py

# Test Tor manager (without actual Tor)
python -c "from src.core.tor_manager import TorManager; tm = TorManager(); print('✓ TorManager imported')"

# Test CLI
arachne --help
arachne status

# Run unit tests
pytest tests/unit/ -v
