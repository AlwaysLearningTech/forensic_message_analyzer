"""
Run manifest generation module.
Creates cryptographic proof of analysis run.
"""

import json
import hashlib
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List

class RunManifestGenerator:
    """Generate cryptographic run manifests."""
    
    def __init__(self, forensic):
        """Initialize manifest generator."""
        self.forensic = forensic
        self.logger = logging.getLogger(__name__)
    
    def generate_manifest(self, df, metrics, screenshots, attachments, output_path: Path) -> Dict[str, Any]:
        """
        Generate comprehensive run manifest.
        
        Args:
            df: Analyzed DataFrame
            metrics: Communication metrics
            screenshots: Processed screenshots
            attachments: Processed attachments
            output_path: Where to save manifest
            
        Returns:
            Generated manifest dictionary
        """
        manifest = {
            'run_id': hashlib.sha256(str(datetime.now()).encode()).hexdigest()[:16],
            'timestamp': datetime.now().isoformat(),
            'version': '1.0.0',
            'analysis_summary': {
                'total_messages': len(df),
                'sources_processed': df['source'].unique().tolist() if 'source' in df.columns else [],
                'screenshots_processed': len(screenshots),
                'attachments_processed': len(attachments),
                'threats_detected': df['threat_detected'].sum() if 'threat_detected' in df.columns else 0,
                'patterns_detected': (df['patterns_detected'] != '').sum() if 'patterns_detected' in df.columns else 0
            },
            'metrics': metrics,
            'file_hashes': self.generate_file_hashes(),
            'integrity_hash': ''
        }
        
        # Calculate overall integrity hash
        manifest_str = json.dumps(manifest, sort_keys=True, default=str)
        manifest['integrity_hash'] = hashlib.sha256(manifest_str.encode()).hexdigest()
        
        # Save manifest
        with open(output_path, 'w') as f:
            json.dump(manifest, f, indent=2, default=str)
        
        self.logger.info(f"Generated run manifest: {output_path}")
        
        self.forensic.record_action(
            "RUN_MANIFEST_GENERATED",
            "manifest",
            f"Manifest ID: {manifest['run_id']}"
        )
        
        return manifest
    
    def generate_file_hashes(self) -> Dict[str, str]:
        """Generate hashes for all output files."""
        hashes = {}
        output_dir = Path("output")
        
        if output_dir.exists():
            for file_path in output_dir.glob("*"):
                if file_path.is_file():
                    with open(file_path, 'rb') as f:
                        file_hash = hashlib.sha256(f.read()).hexdigest()
                        hashes[file_path.name] = file_hash
        
        return hashes