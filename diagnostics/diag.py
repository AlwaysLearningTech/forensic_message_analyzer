#!/usr/bin/env python3
"""
Check what actually exists in the project files
"""
import os
import ast
from pathlib import Path

base_path = Path("/Users/davidsnyder/Library/CloudStorage/OneDrive-Personal/Documents/VSCode/forensic_analyzer_python")

def find_classes_in_file(filepath):
    """Find all class names defined in a Python file"""
    try:
        with open(filepath, 'r') as f:
            tree = ast.parse(f.read())
        return [node.name for node in ast.walk(tree) if isinstance(node, ast.ClassDef)]
    except:
        return []

# Check all extractors
print("=== EXTRACTORS ===")
extractors_path = base_path / "src" / "extractors"
for py_file in extractors_path.glob("*.py"):
    if py_file.name != "__init__.py":
        classes = find_classes_in_file(py_file)
        if classes:
            print(f"{py_file.name}: {', '.join(classes)}")

# Check all analyzers
print("\n=== ANALYZERS ===")
analyzers_path = base_path / "src" / "analyzers"
for py_file in analyzers_path.glob("*.py"):
    if py_file.name != "__init__.py":
        classes = find_classes_in_file(py_file)
        if classes:
            print(f"{py_file.name}: {', '.join(classes)}")

# Check all reporters
print("\n=== REPORTERS ===")
reporters_path = base_path / "src" / "reporters"
for py_file in reporters_path.glob("*.py"):
    if py_file.name != "__init__.py":
        classes = find_classes_in_file(py_file)
        if classes:
            print(f"{py_file.name}: {', '.join(classes)}")

# Check config.py
print("\n=== CONFIG ===")
config_classes = find_classes_in_file(base_path / "src" / "config.py")
print(f"config.py: {', '.join(config_classes) if config_classes else 'NO CLASSES FOUND'}")

# Check what main.py is trying to import
print("\n=== MAIN.PY IMPORTS ===")
main_path = base_path / "src" / "main.py"
with open(main_path, 'r') as f:
    for line in f:
        if 'from src.' in line and 'import' in line:
            print(line.strip())