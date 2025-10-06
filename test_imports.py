#!/usr/bin/env python3
"""
Test script to verify all imports are working correctly
"""
import sys
import os
import traceback

# Add the project root to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_imports():
    print("="*60)
    print("TESTING CORE IMPORTS")
    print("="*60)
    
    errors = []
    warnings = []
    
    # Test 1: Import Config
    try:
        from src.config import Config
        print("✓ Config import successful")
        # Try to instantiate
        config = Config()
        print("✓ Config instantiation successful")
    except ImportError as e:
        print(f"✗ Config import failed: {e}")
        errors.append(("Config", e))
    except Exception as e:
        print(f"✗ Config instantiation failed: {e}")
        errors.append(("Config instantiation", e))
    
    # Test 2: Import ForensicUtils
    try:
        from src.forensic_utils import ForensicUtils
        print("✓ ForensicUtils import successful")
    except ImportError as e:
        print(f"✗ ForensicUtils import failed: {e}")
        errors.append(("ForensicUtils", e))
    
    # Test 3: Import IMessageExtractor
    try:
        from src.extractors.imessage_extractor import IMessageExtractor
        print("✓ IMessageExtractor import successful")
    except ImportError as e:
        print(f"✗ IMessageExtractor import failed: {e}")
        errors.append(("IMessageExtractor", e))
    
    # Test 4: Import ForensicAnalyzer
    try:
        from src.main import ForensicAnalyzer
        print("✓ ForensicAnalyzer import successful")
    except ImportError as e:
        print(f"✗ ForensicAnalyzer import failed: {e}")
        errors.append(("ForensicAnalyzer", e))
        traceback.print_exc()
    
    # Test 5: Try to instantiate ForensicAnalyzer
    if not errors:
        try:
            from src.main import ForensicAnalyzer
            analyzer = ForensicAnalyzer()
            print("✓ ForensicAnalyzer instantiation successful")
        except Exception as e:
            print(f"✗ ForensicAnalyzer instantiation failed: {e}")
            errors.append(("ForensicAnalyzer instantiation", e))
            traceback.print_exc()
    
    # Test optional imports
    print("\n" + "="*60)
    print("TESTING OPTIONAL IMPORTS")
    print("="*60)
    
    try:
        import magic
        print("✓ python-magic import successful")
    except ImportError as e:
        print(f"⚠ python-magic not available: {e}")
        warnings.append("python-magic not installed - run: pip install python-magic-bin")
    
    print("="*60)
    
    if errors:
        print("\n❌ ERRORS FOUND:")
        for name, error in errors:
            print(f"  - {name}: {error}")
        return False
    else:
        print("\n✅ ALL CORE TESTS PASSED!")
        if warnings:
            print("\n⚠ Warnings:")
            for warning in warnings:
                print(f"  - {warning}")
        print("\nYou can now run:")
        print("  python3 run.py")
        print("  # or")
        print("  python3 -c \"from src.main import ForensicAnalyzer; analyzer = ForensicAnalyzer(); analyzer.run_analysis()\"")
        return True

if __name__ == "__main__":
    success = test_imports()
    sys.exit(0 if success else 1)