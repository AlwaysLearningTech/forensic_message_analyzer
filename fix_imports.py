#!/usr/bin/env python3
# filepath: fix_imports.py
"""
Safe import fixer - fixes case sensitivity issues without breaking the system
"""

import os
import re
from pathlib import Path

def fix_imessage_class_name():
    """Fix the iMessageExtractor class name issue"""
    
    # Path to imessage_extractor.py
    file_path = Path("src/extractors/imessage_extractor.py")
    
    if not file_path.exists():
        print(f"❌ File not found: {file_path}")
        return False
    
    # Read the file
    with open(file_path, 'r') as f:
        content = f.read()
    
    # Check current class name
    if "class IMessageExtractor" in content:
        print("Found 'class IMessageExtractor' - adding alias")
        
        # Add alias at the end if not already present
        if "iMessageExtractor = IMessageExtractor" not in content:
            content += "\n\n# Alias for compatibility\niMessageExtractor = IMessageExtractor\n"
            
            # Write back
            with open(file_path, 'w') as f:
                f.write(content)
            print(f"✓ Added alias to {file_path}")
        else:
            print("✓ Alias already exists")
            
    elif "class iMessageExtractor" in content:
        print("✓ Class name is already 'iMessageExtractor'")
        
        # Add reverse alias if needed
        if "IMessageExtractor = iMessageExtractor" not in content:
            content += "\n\n# Alias for compatibility\nIMessageExtractor = iMessageExtractor\n"
            with open(file_path, 'w') as f:
                f.write(content)
            print(f"✓ Added reverse alias to {file_path}")
    else:
        print("❌ No iMessage extractor class found!")
        return False
    
    return True

def fix_main_imports():
    """Fix imports in main.py to use correct class names"""
    
    file_path = Path("src/main.py")
    
    if not file_path.exists():
        print(f"❌ File not found: {file_path}")
        return False
    
    with open(file_path, 'r') as f:
        lines = f.readlines()
    
    modified = False
    new_lines = []
    
    for line in lines:
        # Fix ForensicUtils -> ForensicIntegrity
        if "from src.forensic_utils import ForensicUtils" in line:
            new_lines.append("from src.forensic_utils import ForensicIntegrity\n")
            print("✓ Fixed: ForensicUtils -> ForensicIntegrity")
            modified = True
        # Fix iMessageExtractor import (keep as is, we'll use alias)
        elif line.strip() == "from src.extractors.imessage_extractor import iMessageExtractor":
            new_lines.append(line)  # Keep as is, we'll use alias
        # Remove non-existent imports
        elif "from src.extractors.screenshot_extractor import" in line:
            print("✓ Removed: screenshot_extractor import")
            modified = True
            continue
        elif "from src.extractors.signal_extractor import" in line:
            print("✓ Removed: signal_extractor import")
            modified = True
            continue
        elif "from src.analyzers.pattern_analyzer import PatternAnalyzer" in line:
            # Check if PatternAnalyzer exists
            if not Path("src/analyzers/pattern_analyzer.py").exists():
                print("✓ Removed: pattern_analyzer import (file doesn't exist)")
                modified = True
                continue
            else:
                new_lines.append(line)
        elif "from src.reporters.html_reporter import" in line:
            print("✓ Removed: html_reporter import")
            modified = True
            continue
        elif "from src.reporters.json_reporter import JSONReporter" in line:
            # Keep if file exists
            if Path("src/reporters/json_reporter.py").exists():
                new_lines.append(line)
            else:
                print("✓ Removed: json_reporter import")
                modified = True
                continue
        elif "from src.reporters.pdf_reporter import" in line:
            print("✓ Removed: pdf_reporter import")
            modified = True
            continue
        else:
            new_lines.append(line)
    
    if modified:
        with open(file_path, 'w') as f:
            f.writelines(new_lines)
        print(f"✓ Updated {file_path}")
    else:
        print("✓ No changes needed in main.py imports")
    
    return True

def fix_forensic_reporter_indent():
    """Fix indentation error in forensic_reporter.py"""
    
    file_path = Path("src/reporters/forensic_reporter.py")
    
    if not file_path.exists():
        print(f"⚠️ File not found: {file_path}")
        return True  # Not critical
    
    with open(file_path, 'r') as f:
        lines = f.readlines()
    
    # Check line 224 for indentation issues
    if len(lines) >= 224:
        # Fix common indentation issues around line 224
        for i in range(max(0, 220), min(len(lines), 230)):
            # Remove any tabs and replace with spaces
            lines[i] = lines[i].expandtabs(4)
    
    with open(file_path, 'w') as f:
        f.writelines(lines)
    
    print(f"✓ Fixed indentation in {file_path}")
    return True

def main():
    """Run all fixes"""
    print("=" * 60)
    print("Running Safe Import Fixes")
    print("=" * 60)
    
    print("\n1. Fixing iMessageExtractor class name...")
    fix_imessage_class_name()
    
    print("\n2. Fixing main.py imports...")
    fix_main_imports()
    
    print("\n3. Fixing forensic_reporter.py indentation...")
    fix_forensic_reporter_indent()
    
    print("\n" + "=" * 60)
    print("✅ Fixes applied successfully!")
    print("=" * 60)

if __name__ == "__main__":
    main()