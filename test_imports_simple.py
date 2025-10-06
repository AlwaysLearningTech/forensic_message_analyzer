#!/usr/bin/env python3
# filepath: test_imports_simple.py
"""
Simple test to check if imports work
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path.cwd()))

def test_imports():
    """Test each import individually"""
    
    results = []
    
    # Test 1: Config
    try:
        from src.config import Config
        results.append("✓ Config")
    except Exception as e:
        results.append(f"✗ Config: {e}")
    
    # Test 2: ForensicIntegrity
    try:
        from src.forensic_utils import ForensicIntegrity
        results.append("✓ ForensicIntegrity")
    except Exception as e:
        results.append(f"✗ ForensicIntegrity: {e}")
    
    # Test 3: iMessageExtractor
    try:
        from src.extractors.imessage_extractor import iMessageExtractor
        results.append("✓ iMessageExtractor")
    except Exception as e:
        results.append(f"✗ iMessageExtractor: {e}")
    
    # Test 4: Main module
    try:
        from src.main import ForensicAnalyzer
        results.append("✓ ForensicAnalyzer")
    except Exception as e:
        results.append(f"✗ ForensicAnalyzer: {e}")
    
    # Print results
    print("\nImport Test Results:")
    print("=" * 40)
    for result in results:
        print(result)
    
    # Check if all passed
    if all("✓" in r for r in results):
        print("\n✅ All imports successful!")
        return True
    else:
        print("\n❌ Some imports failed")
        return False

if __name__ == "__main__":
    success = test_imports()
    sys.exit(0 if success else 1)