#!/bin/bash
# Comprehensive test suite for forensic message analyzer

echo "=================================================="
echo "Forensic Message Analyzer - Complete Test Suite"
echo "=================================================="
echo "Date: $(date)"
echo ""

cd /Users/davidsnyder/workspace/repos/forensic_message_analyzer || { echo "Failed to change directory"; exit 1; }

# Color codes for output
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Summary
echo "=================================================="
echo "Running FULL test suite (all test files)..."
echo "=================================================="
echo ""

python3 -m pytest tests/ -v --tb=short
EXIT_CODE=$?

echo ""
echo "=================================================="
echo "TEST SUMMARY"
echo "=================================================="

if [ $EXIT_CODE -eq 0 ]; then
    echo -e "${GREEN}✓ All test suites passed!${NC}"
    echo ""
    echo "The system is ready for use."
    echo "Next steps:"
    echo "  1. Configure your .env file with data paths"
    echo "  2. Place source data in configured directories"
    echo "  3. Run: python3 run.py"
    exit 0
else
    echo -e "${RED}✗ Some tests failed.${NC}"
    echo ""
    echo "Please review the failing tests before proceeding."
    echo "Run with -v flag for detailed output:"
    echo "  python3 -m pytest tests/ -v"
    exit 1
fi