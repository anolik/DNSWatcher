#!/bin/bash
# Environment setup for SPF/DMARC/DKIM Watcher

echo "Setting up SPF/DMARC/DKIM Watcher..."

# Check Python version
python3 --version 2>/dev/null || python --version 2>/dev/null || { echo "Python not found"; exit 1; }

# Create virtual environment
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv 2>/dev/null || python -m venv venv
fi

# Activate virtual environment
if [ -f "venv/bin/activate" ]; then
    source venv/bin/activate
elif [ -f "venv/Scripts/activate" ]; then
    source venv/Scripts/activate
fi

# Install dependencies
echo "Installing dependencies..."
pip install -r requirements.txt

# Initialize database
echo "Initializing database..."
python init_db.py

# Set development environment
export FLASK_ENV=development
export FLASK_DEBUG=1
export SECRET_KEY=dev-secret-key-change-in-production

echo "Setup complete"
echo "Run 'python create_admin.py' to create your first admin user"
echo "Run 'python wsgi.py' to start the development server"
