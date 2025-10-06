#!/bin/bash
# Verify the forensic message analyzer setup and run essential tests

echo "=================================================="
echo "Forensic Message Analyzer - Setup Verification"
echo "=================================================="

cd /Users/davidsnyder/workspace/repos/forensic_message_analyzer || { echo "Failed to change directory"; exit 1; }

# Check Python version
echo ""
echo "1. Checking Python version..."
python3 --version

# Check if virtual environment is recommended
echo ""
echo "2. Checking for virtual environment..."
if [ -d "venv" ]; then
    echo "✓ Virtual environment found"
else
    echo "ℹ Virtual environment not found (optional)"
fi

# Check required packages
echo ""
echo "3. Checking required packages..."
python3 -c "
import sys
packages = {
    'pandas': 'Data processing',
    'pytest': 'Testing framework',
    'python-dotenv': 'Environment configuration',
    'textblob': 'Sentiment analysis',
    'Pillow': 'Image processing',
    'pytesseract': 'OCR capabilities',
    'openpyxl': 'Excel reports',
    'python-docx': 'Word reports',
}

missing = []
for pkg, desc in packages.items():
    try:
        __import__(pkg.replace('-', '_'))
        print(f'✓ {pkg}: {desc}')
    except ImportError:
        print(f'✗ {pkg}: {desc} - MISSING')
        missing.append(pkg)

if missing:
    print('\nTo install missing packages:')
    print(f'pip install {' '.join(missing)}')
    sys.exit(1)
"

# Check configuration
echo ""
echo "4. Checking configuration..."
if [ -f ".env" ]; then
    echo "✓ .env file found"
else
    echo "✗ .env file not found"
    echo "  Create one from .env.example:"
    echo "  cp .env.example .env"
fi

# Run essential tests
echo ""
echo "5. Running essential tests..."
echo ""

# Test imports
echo "Testing imports..."
python3 -m pytest tests/test_imports.py -q

# Test core functionality
echo "Testing core functionality..."
python3 -m pytest tests/test_core_functionality.py -q

# Test integration
echo "Testing integration..."
python3 -m pytest tests/test_integration.py -q

# Summary
echo ""
echo "=================================================="
echo "Setup Verification Complete"
echo "=================================================="
echo ""
echo "Next steps:"
echo "1. Ensure .env file is configured with your data paths"
echo "2. Place source data in configured directories"
echo "3. Run: python3 run.py"