#!/bin/bash
# Run essential tests for forensic message analyzer

echo "=================================================="
echo "Running Essential Tests for Forensic Message Analyzer"
echo "=================================================="

cd /Users/davidsnyder/workspace/repos/forensic_message_analyzer || { echo "Failed to change directory. Exiting."; exit 1; }

echo ""
echo "1. Testing imports and dependencies..."
python3 -m pytest tests/test_imports.py -v

echo ""
echo "2. Testing core functionality..."
python3 -m pytest tests/test_core_functionality.py -v

echo ""
echo "3. Testing integration..."
python3 -m pytest tests/test_integration.py -v

echo ""
echo "=================================================="
echo "Test Summary"
echo "=================================================="
python3 -m pytest tests/test_imports.py tests/test_core_functionality.py tests/test_integration.py --tb=no -q

echo ""
echo "Done! If all tests pass, the system is ready to use."