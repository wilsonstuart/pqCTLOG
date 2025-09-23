#!/bin/bash

# Create a virtual environment
python -m venv venv

# Activate the virtual environment
source venv/bin/activate  # On Windows: .\venv\Scripts\activate

# Upgrade pip and install development dependencies
pip install --upgrade pip
pip install -e ".[dev]"

# Create a local .env file if it doesn't exist
if [ ! -f .env ]; then
    cp .env.example .env
    echo "Created .env file from .env.example"
fi

echo "Development environment setup complete!"
echo "To start the application, run: docker-compose -f docker-compose.yml -f docker-compose.dev.yml up --build"
