#!/usr/bin/env python3
"""
Comprehensive diagnostic tool to identify and fix all import issues.
"""
import os
import sys
import importlib
import traceback
from pathlib import Path

# Add the project root to Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

def test_module_import(module_path: str, class_name: str = None):
    """Test if a module can be imported and optionally if a class exists."""
    try:
        module = importlib.import_module(module_path)
        print(f"✓ Module {module_path} imported successfully")
        
        if class_name:
            if hasattr(module, class_name):
                print(f"  ✓ Class {class_name} found")
                return True, None
            else:
                available = [item for item in dir(module) if not item.startswith('_')]
                error = f"Class {class_name} not found. Available: {available}"
                print(f"  ✗ {error}")
                return False, error
        return True, None
    except ImportError as e:
        print(f"✗ Module {module_path} failed: {e}")
        return False, str(e)
    except Exception as e:
        print(f"✗ Unexpected error for {module_path}: {e}")
        return False, str(e)

def main():
    print("=" * 60)
    print("COMPREHENSIVE FORENSIC ANALYZER DIAGNOSTIC")
    print("=" * 60)
    
    issues = []
    
    # Test config
    print("\n=== TESTING CONFIG ===")
    success, error = test_module_import("src.config", "Config")
    if not success:
        issues.append(("Config", error))
    
    # Test forensic utils
    print("\n=== TESTING FORENSIC UTILS ===")
    # First check what's actually in forensic_utils
    try:
        import src.forensic_utils as fu
        available_classes = [item for item in dir(fu) if not item.startswith('_')]
        print(f"Available in forensic_utils: {available_classes}")
    except:
        pass
    
    success, error = test_module_import("src.forensic_utils", "ForensicUtils")
    if not success:
        # Try the correct class name
        success, error = test_module_import("src.forensic_utils", "ForensicIntegrity")
        if not success:
            issues.append(("ForensicUtils/ForensicIntegrity", error))
    
    # Test extractors
    print("\n=== TESTING EXTRACTORS ===")
    extractors = [
        ("src.extractors.imessage_extractor", "iMessageExtractor"),
        ("src.extractors.whatsapp_extractor", "WhatsAppExtractor"),
        ("src.extractors.data_extractor", "DataExtractor"),
        ("src.extractors.screenshot_extractor", "ScreenshotExtractor"),  # Likely missing
        ("src.extractors.signal_extractor", "SignalExtractor"),  # Likely missing
    ]
    
    for module_path, class_name in extractors:
        success, error = test_module_import(module_path, class_name)
        if not success:
            issues.append((f"{module_path}.{class_name}", error))
    
    # Test analyzers
    print("\n=== TESTING ANALYZERS ===")
    analyzers = [
        ("src.analyzers.threat_analyzer", "ThreatAnalyzer"),
        ("src.analyzers.pattern_analyzer", "PatternAnalyzer"),  # Likely missing
        ("src.analyzers.sentiment_analyzer", "SentimentAnalyzer"),
        ("src.analyzers.behavioral_analyzer", "BehavioralAnalyzer"),
        ("src.analyzers.screenshot_analyzer", "ScreenshotAnalyzer"),
        ("src.analyzers.yaml_pattern_analyzer", "YamlPatternAnalyzer"),
        ("src.analyzers.attachment_processor", "AttachmentProcessor"),
        ("src.analyzers.communication_metrics", "CommunicationMetricsGenerator"),
    ]
    
    for module_path, class_name in analyzers:
        success, error = test_module_import(module_path, class_name)
        if not success:
            issues.append((f"{module_path}.{class_name}", error))
    
    # Test reporters
    print("\n=== TESTING REPORTERS ===")
    # Check if forensic_reporter exists
    reporter_dir = project_root / "src" / "reporters"
    actual_reporters = list(reporter_dir.glob("*.py"))
    print(f"Actual reporter files found: {[f.name for f in actual_reporters if f.name != '__init__.py']}")
    
    reporters = [
        ("src.reporters.html_reporter", "HTMLReporter"),  # Likely missing
        ("src.reporters.json_reporter", "JSONReporter"),  # Likely missing
        ("src.reporters.pdf_reporter", "PDFReporter"),    # Likely missing
        ("src.reporters.forensic_reporter", "ForensicReporter"),  # Should exist
    ]
    
    for module_path, class_name in reporters:
        success, error = test_module_import(module_path, class_name)
        if not success:
            issues.append((f"{module_path}.{class_name}", error))
    
    # Summary
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    
    if issues:
        print(f"\n❌ Found {len(issues)} issues:\n")
        for item, error in issues:
            print(f"  • {item}: {error}")
        
        print("\n🔧 RECOMMENDED FIXES:")
        print("1. Update main.py to use correct class names")
        print("2. Create missing extractors or remove their imports")
        print("3. Create missing reporters or use ForensicReporter")
        print("4. Fix ForensicUtils -> ForensicIntegrity")
    else:
        print("\n✅ All imports are working correctly!")
    
    return len(issues) == 0

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)