"""
JSON reporter stub
"""
import json
from pathlib import Path
from typing import Any

class JSONReporter:
    """Simple JSON reporter"""
    
    def __init__(self):
        pass
        
    def generate_report(self, data: Any, output_path: Path):
        """Generate JSON report"""
        output_file = output_path / "report.json"
        with open(output_file, 'w') as f:
            json.dump(data, f, indent=2, default=str)
        return output_file