#!/bin/bash

# Define colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${GREEN}Starting SigmaAssistant Setup for Mac...${NC}"

# Check for Python 3
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}Python 3 is not installed. Please install it first.${NC}"
    exit 1
fi

# Create virtual environment if it doesn't exist
if [ ! -d ".venv" ]; then
    echo -e "${YELLOW}Creating virtual environment...${NC}"
    python3 -m venv .venv
else
    echo -e "${GREEN}Virtual environment found.${NC}"
fi

# Activate virtual environment
source .venv/bin/activate

# Install dependencies
if [ -f "requirements.txt" ]; then
    echo -e "${YELLOW}Installing dependencies...${NC}"
    pip install -r requirements.txt
else
    echo -e "${RED}requirements.txt not found!${NC}"
    exit 1
fi

# Check for .env file
if [ ! -f ".env" ]; then
    echo -e "${YELLOW}No .env file found. Creating from template...${NC}"
    if [ -f ".env.example" ]; then
        cp .env.example .env
        echo -e "${GREEN}Created .env from .env.example. Please update it with your API keys.${NC}"
    else
        echo -e "${RED}No .env.example found. Please create .env manually.${NC}"
        # Create a dummy .env if none exists to prevent crash
        echo "GEMINI_API_KEY=YOUR_API_KEY_HERE" > .env
        echo -e "${YELLOW}Created a template .env. Please edit it.${NC}"
    fi
fi

# Run the application
echo -e "${GREEN}Starting SigmaAssistant...${NC}"
# Use the python from the venv to run uvicorn
python -m uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000
