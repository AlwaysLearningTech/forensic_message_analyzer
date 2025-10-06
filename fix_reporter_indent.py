#!/usr/bin/env python3
# filepath: fix_reporter_indent.py
"""
Fix the specific indentation issue in forensic_reporter.py at line 224
"""

from pathlib import Path

def fix_reporter_indentation():
    """Fix the specific indentation error at line 224"""
    
    file_path = Path("src/reporters/forensic_reporter.py")
    
    if not file_path.exists():
        print(f"❌ File not found: {file_path}")
        return False
    
    # Read the file
    with open(file_path, 'r') as f:
        lines = f.readlines()
    
    print(f"Total lines in file: {len(lines)}")
    
    # Show context around line 224
    if len(lines) >= 224:
        print("\nContext around line 224:")
        for i in range(max(0, 220), min(len(lines), 228)):
            # Show line with number
            line = lines[i].rstrip()
            if i == 223:  # Line 224 (0-indexed)
                print(f">>> {i+1}: {repr(line)}")
                # Check for indentation issues
                if line and not line[0].isspace() and not line.startswith(('def ', 'class ', 'import ', 'from ', '#')):
                    print(f"    ^ Possible issue: Line doesn't start with expected keyword")
                elif line.startswith('\t'):
                    print(f"    ^ Issue: Line starts with tab character")
                elif line and line[0] == ' ':
                    spaces = len(line) - len(line.lstrip())
                    if spaces % 4 != 0:
                        print(f"    ^ Issue: Indentation is {spaces} spaces (not multiple of 4)")
            else:
                print(f"{i+1:3}: {repr(line)}")
    
    # Try to fix common issues
    print("\nAttempting automatic fix...")
    
    # Fix lines around 224
    for i in range(max(0, 220), min(len(lines), 230)):
        # Replace tabs with 4 spaces
        lines[i] = lines[i].expandtabs(4)
        
        # Fix specific line 224 if it has issues
        if i == 223:  # Line 224 (0-indexed)
            line = lines[i]
            stripped = line.lstrip()
            
            # If line is not empty and has content
            if stripped and not stripped.startswith('#'):
                # Count indentation of previous non-empty line
                prev_indent = 0
                for j in range(i-1, -1, -1):
                    if lines[j].strip():
                        prev_indent = len(lines[j]) - len(lines[j].lstrip())
                        break
                
                # Check if this looks like it should be indented
                if stripped.startswith(('return', 'pass', 'continue', 'break', 'raise')):
                    # These should typically be indented at least 4 spaces
                    if prev_indent >= 4:
                        lines[i] = ' ' * prev_indent + stripped + '\n'
                elif stripped.startswith(('except', 'elif', 'else', 'finally')):
                    # These should align with try/if blocks
                    lines[i] = ' ' * max(0, prev_indent - 4) + stripped + '\n'
                elif not line[0].isspace() and not stripped.startswith(('def ', 'class ')):
                    # This line should probably be indented
                    lines[i] = ' ' * (prev_indent) + stripped + '\n'
    
    # Write back
    with open(file_path, 'w') as f:
        f.writelines(lines)
    
    print("✓ Applied fixes to forensic_reporter.py")
    return True

def main():
    """Run the fix"""
    print("=" * 60)
    print("Fixing forensic_reporter.py indentation issue")
    print("=" * 60)
    
    if fix_reporter_indentation():
        print("\n✅ Fix applied!")
    else:
        print("\n❌ Fix failed!")

if __name__ == "__main__":
    main()