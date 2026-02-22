"""
Screenshot OCR and analysis module.
Extracts text from screenshots and analyzes content.
"""

import logging
from pathlib import Path
from typing import List, Dict, Any
import pytesseract
from PIL import Image
import hashlib
from datetime import datetime

class ScreenshotAnalyzer:
    """Analyzes screenshots using OCR."""
    
    def __init__(self, forensic):
        """Initialize screenshot analyzer."""
        self.forensic = forensic
        self.logger = logging.getLogger(__name__)
        self.screenshots_dir = Path("source_files/screenshots")
        
        self.forensic.record_action(
            "SCREENSHOT_ANALYZER_INIT",
            "Initialized screenshot OCR analyzer"
        )
    
    def analyze_screenshots(self) -> List[Dict[str, Any]]:
        """
        Analyze all screenshots in the source directory.
        
        Returns:
            List of analyzed screenshot data
        """
        results = []
        
        if not self.screenshots_dir.exists():
            self.logger.warning(f"Screenshots directory not found: {self.screenshots_dir}")
            return results
        
        image_extensions = ['.png', '.jpg', '.jpeg', '.gif', '.bmp']
        image_files = [f for f in self.screenshots_dir.iterdir() 
                      if f.suffix.lower() in image_extensions]
        
        self.logger.info(f"Found {len(image_files)} screenshots to analyze")
        
        for image_file in image_files:
            try:
                # Calculate hash for integrity
                with open(image_file, 'rb') as f:
                    file_hash = hashlib.sha256(f.read()).hexdigest()
                
                # Extract text using OCR
                image = Image.open(image_file)
                extracted_text = pytesseract.image_to_string(image)
                
                # Extract metadata from filename if available
                filename = image_file.name
                date_extracted = None
                if 'Screenshot_' in filename:
                    # Try to extract date from filename
                    try:
                        date_str = filename.split('_')[1].split('-')[0]
                        date_extracted = datetime.strptime(date_str, '%Y%m%d')
                    except:
                        pass
                
                result = {
                    'filename': filename,
                    'filepath': str(image_file),
                    'file_hash': file_hash,
                    'extracted_text': extracted_text,
                    'text_length': len(extracted_text),
                    'date_extracted': date_extracted,
                    'processing_timestamp': datetime.now().isoformat(),
                    'source': 'screenshot'
                }
                
                results.append(result)
                
                self.forensic.record_action(
                    "SCREENSHOT_PROCESSED",
                    f"Processed {filename}: {len(extracted_text)} chars extracted"
                )
                
            except Exception as e:
                self.logger.error(f"Failed to process {image_file}: {e}")
                self.forensic.record_action(
                    "SCREENSHOT_PROCESSING_FAILED",
                    f"Failed to process {image_file.name}: {str(e)}"
                )
        
        self.logger.info(f"Successfully analyzed {len(results)} screenshots")
        return results