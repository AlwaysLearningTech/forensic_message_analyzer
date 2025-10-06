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

# Track overall results
TESTS_PASSED=0
TESTS_FAILED=0

echo "Running Test Suite..."
echo "=================================================="
echo ""

# 1. Import tests
echo "1. Testing imports and dependencies..."
if python3 -m pytest tests/test_imports.py -q --tb=no; then
    echo -e "${GREEN}✓${NC} Import tests passed"
    ((TESTS_PASSED++))
else
    echo -e "${RED}✗${NC} Import tests failed"
    ((TESTS_FAILED++))
fi
echo ""

# 2. Core functionality tests
echo "2. Testing core functionality..."
if python3 -m pytest tests/test_core_functionality.py -q --tb=no; then
    echo -e "${GREEN}✓${NC} Core functionality tests passed"
    ((TESTS_PASSED++))
else
    echo -e "${RED}✗${NC} Core functionality tests failed"
    ((TESTS_FAILED++))
fi
echo ""

# 3. Integration tests
echo "3. Testing integration..."
if python3 -m pytest tests/test_integration.py -q --tb=no; then
    echo -e "${GREEN}✓${NC} Integration tests passed"
    ((TESTS_PASSED++))
else
    echo -e "${RED}✗${NC} Integration tests failed"
    ((TESTS_FAILED++))
fi
echo ""

# 4. Forensic utils tests (if exists)
if [ -f "tests/test_forensic_utils.py" ]; then
    echo "4. Testing forensic utilities..."
    if python3 -m pytest tests/test_forensic_utils.py -q --tb=no; then
        echo -e "${GREEN}✓${NC} Forensic utils tests passed"
        ((TESTS_PASSED++))
    else
        echo -e "${RED}✗${NC} Forensic utils tests failed"
        ((TESTS_FAILED++))
    fi
    echo ""
fi

# Summary
echo "=================================================="
echo "TEST SUMMARY"
echo "=================================================="
echo -e "Tests Passed: ${GREEN}${TESTS_PASSED}${NC}"
echo -e "Tests Failed: ${RED}${TESTS_FAILED}${NC}"
echo ""

# Overall status
if [ $TESTS_FAILED -eq 0 ]; then
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