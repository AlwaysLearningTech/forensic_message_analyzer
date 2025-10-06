#!/usr/bin/env python3
"""
System readiness check for Forensic Message Analyzer.
Verifies configuration, dependencies, and data directories.
"""

import sys
import os
from pathlib import Path
from datetime import datetime

def check_python_version():
    """Check if Python version is adequate."""
    version = sys.version_info
    if version.major == 3 and version.minor >= 9:
        return True, f"Python {version.major}.{version.minor}.{version.micro}"
    return False, f"Python {version.major}.{version.minor}.{version.micro} (3.9+ required)"

def check_imports():
    """Check if all required packages are installed."""
    required_packages = [
        ('pandas', 'Data processing'),
        ('pytest', 'Testing framework'),
        ('python-dotenv', 'Environment configuration', 'dotenv'),
        ('textblob', 'Sentiment analysis', 'textblob'),
        ('Pillow', 'Image processing', 'PIL'),
        ('pytesseract', 'OCR capabilities', 'pytesseract'),
        ('openpyxl', 'Excel reports', 'openpyxl'),
        ('python-docx', 'Word reports', 'docx'),
    ]
    
    results = []
    missing = []
    
    for package_info in required_packages:
        package = package_info[0]
        description = package_info[1]
        import_name = package_info[2] if len(package_info) > 2 else package.replace('-', '_')
        
        try:
            __import__(import_name)
            results.append((package, description, True))
        except ImportError:
            results.append((package, description, False))
            missing.append(package)
    
    return results, missing

def check_configuration():
    """Check if configuration files exist."""
    checks = []
    
    # Check for .env file in data directory (correct location)
    env_file_data = Path.home() / 'workspace/data/forensic_message_analyzer/.env'
    checks.append(('.env file (data dir)', env_file_data.exists()))
    
    # Also check for local .env (for backward compatibility)
    env_file_local = Path('.env')
    if env_file_local.exists():
        checks.append(('.env file (local)', True))
    
    # Check for .env.example
    env_example = Path('.env.example')
    checks.append(('.env.example', env_example.exists()))
    
    # Check for config.py
    config_py = Path('src/config.py')
    checks.append(('src/config.py', config_py.exists()))
    
    return checks, env_file_data.exists()

def check_directories():
    """Check if required directories exist or can be created."""
    # Set DOTENV_PATH environment variable for Config to find the right .env
    os.environ['DOTENV_PATH'] = str(Path.home() / 'workspace/data/forensic_message_analyzer/.env')
    
    from src.config import Config
    
    config = Config()
    checks = []
    
    # Output directory
    if config.output_dir:
        output_path = Path(config.output_dir)
        checks.append((f'Output directory: {output_path}', output_path.exists()))
    
    # Review directory
    if config.review_dir:
        review_path = Path(config.review_dir)
        checks.append((f'Review directory: {review_path}', review_path.exists()))
    
    # Source directories
    if hasattr(config, 'whatsapp_source_dir') and config.whatsapp_source_dir:
        whatsapp_path = Path(config.whatsapp_source_dir).expanduser()
        checks.append((f'WhatsApp source: {whatsapp_path}', whatsapp_path.exists()))
    
    if hasattr(config, 'screenshot_source_dir') and config.screenshot_source_dir:
        screenshot_path = Path(config.screenshot_source_dir).expanduser()
        checks.append((f'Screenshot source: {screenshot_path}', screenshot_path.exists()))
    
    # iMessage database
    if hasattr(config, 'messages_db_path') and config.messages_db_path:
        messages_path = Path(config.messages_db_path).expanduser()
        checks.append((f'iMessage database: {messages_path}', messages_path.exists()))
    
    return checks

def main():
    """Run all readiness checks."""
    print("=" * 60)
    print("FORENSIC MESSAGE ANALYZER - SYSTEM READINESS CHECK")
    print("=" * 60)
    print(f"Timestamp: {datetime.now().isoformat()}")
    print()
    
    all_good = True
    
    # Check Python version
    print("1. Python Version")
    print("-" * 40)
    version_ok, version_info = check_python_version()
    status = "✓" if version_ok else "✗"
    print(f"{status} {version_info}")
    if not version_ok:
        all_good = False
    print()
    
    # Check imports
    print("2. Required Packages")
    print("-" * 40)
    results, missing = check_imports()
    for package, description, installed in results:
        status = "✓" if installed else "✗"
        print(f"{status} {package}: {description}")
    
    if missing:
        all_good = False
        print(f"\nTo install missing packages:")
        print(f"  pip install {' '.join(missing)}")
    print()
    
    # Check configuration
    print("3. Configuration Files")
    print("-" * 40)
    config_checks, env_found = check_configuration()
    for item, exists in config_checks:
        status = "✓" if exists else "✗"
        print(f"{status} {item}")
    
    if not env_found:
        all_good = False
        print("\nNote: .env file should be in ~/workspace/data/forensic_message_analyzer/")
        print("If you need to create it:")
        print("  cp .env.example ~/workspace/data/forensic_message_analyzer/.env")
        print("  # Then edit it with your settings")
    print()
    
    # Check directories
    print("4. Data Directories")
    print("-" * 40)
    try:
        dir_checks = check_directories()
        for item, exists in dir_checks:
            status = "✓" if exists else "ℹ"
            print(f"{status} {item}")
        
        if not all(check[1] for check in dir_checks if 'Output' in check[0] or 'Review' in check[0]):
            print("\nNote: Output/Review directories will be created automatically when needed.")
        
        # Check for source data
        source_missing = [check[0] for check in dir_checks if ('source' in check[0].lower() or 'iMessage' in check[0]) and not check[1]]
        if source_missing:
            print("\n⚠ Missing source data directories:")
            for missing in source_missing:
                print(f"  - {missing}")
            print("\nEnsure your source data is placed in the configured locations.")
            
    except Exception as e:
        print(f"✗ Could not check directories: {e}")
        print("  Ensure .env file is configured properly.")
        all_good = False
    print()
    
    # Final status
    print("=" * 60)
    if all_good:
        print("✓ SYSTEM READY")
        print("\nNext steps:")
        print("  1. Ensure source data is in configured directories")
        print("  2. Run tests: ./tests/run_all_tests.sh")
        print("  3. Run analysis: python3 run.py")
    else:
        print("✗ SYSTEM NOT FULLY READY")
        print("\nPlease address any issues above before proceeding.")
        print("You can still run tests to verify core functionality:")
        print("  python3 -m pytest tests/test_core_functionality.py -v")
    print("=" * 60)
    
    return 0 if all_good else 1

if __name__ == "__main__":
    sys.exit(main())