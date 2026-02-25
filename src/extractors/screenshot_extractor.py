#!/usr/bin/env python3
"""Screenshot extraction and cataloging module."""

from pathlib import Path
from typing import List, Dict, Optional
from datetime import datetime, timezone
import hashlib
import re
from PIL import Image
from ..forensic_utils import ForensicRecorder

class ScreenshotExtractor:
    """Extract and catalog screenshots for analysis."""
    
    def __init__(self, screenshot_dir: str, forensic_recorder: ForensicRecorder):
        """
        Initialize screenshot extractor.
        
        Args:
            screenshot_dir: Directory containing screenshots
            forensic_recorder: ForensicRecorder instance
        """
        self.screenshot_dir = Path(screenshot_dir) if screenshot_dir else None
        self.forensic = forensic_recorder
        
    def extract_screenshots(self) -> List[Dict]:
        """
        Extract screenshots from the configured directory.
        
        Returns:
            List of screenshot metadata dictionaries
        """
        screenshots = []
        
        if not self.screenshot_dir or not self.screenshot_dir.exists():
            self.forensic.record_action(
                "screenshot_extraction_error",
                f"Screenshot directory not found: {self.screenshot_dir}"
            )
            return screenshots
        
        # Common image extensions
        image_extensions = {'.png', '.jpg', '.jpeg', '.gif', '.bmp', '.tiff'}
        
        for file_path in self.screenshot_dir.iterdir():
            if file_path.suffix.lower() in image_extensions:
                try:
                    metadata = self._extract_metadata(file_path)
                    if metadata:
                        screenshots.append(metadata)
                        self.forensic.record_action(
                            "screenshot_extracted",
                            f"Extracted screenshot: {file_path.name}"
                        )
                except Exception as e:
                    self.forensic.record_action(
                        "screenshot_extraction_error",
                        f"Error extracting {file_path.name}: {str(e)}"
                    )
        
        self.forensic.record_action(
            "screenshot_extraction_complete",
            f"Extracted {len(screenshots)} screenshots"
        )
        
        return screenshots
    
    def _extract_metadata(self, file_path: Path) -> Optional[Dict]:
        """
        Extract metadata from a screenshot file.
        
        Args:
            file_path: Path to the screenshot file
            
        Returns:
            Dictionary containing screenshot metadata
        """
        try:
            # Calculate file hash
            with open(file_path, 'rb') as f:
                file_hash = hashlib.sha256(f.read()).hexdigest()
            
            # Get file stats
            stats = file_path.stat()
            
            # Extract date from filename if present
            date_extracted = self._extract_date_from_filename(file_path.name)
            
            # Try to get image metadata
            image_metadata = {}
            try:
                with Image.open(file_path) as img:
                    image_metadata = {
                        'width': img.width,
                        'height': img.height,
                        'format': img.format,
                        'mode': img.mode,
                        'exif': {}
                    }
                    
                    # Extract EXIF data if available (public API since Pillow 6.0)
                    exif = img.getexif()
                    if exif:
                        from PIL.ExifTags import TAGS
                        for tag_id, value in exif.items():
                            tag = TAGS.get(tag_id, tag_id)
                            image_metadata['exif'][tag] = str(value)
            except Exception as e:
                self.forensic.record_action(
                    "image_metadata_error",
                    f"Could not extract image metadata from {file_path.name}: {str(e)}"
                )
            
            metadata = {
                'filename': file_path.name,
                'path': str(file_path),
                'hash': file_hash,
                'size_bytes': stats.st_size,
                'created_time': datetime.fromtimestamp(stats.st_ctime, tz=timezone.utc).isoformat(),
                'modified_time': datetime.fromtimestamp(stats.st_mtime, tz=timezone.utc).isoformat(),
                'extracted_date': date_extracted,
                'file_type': file_path.suffix.lower(),
                'image_metadata': image_metadata,
                'requires_ocr': True,  # Flag for OCR processing
                'extracted_text': None  # Will be filled by OCR analyzer
            }
            
            return metadata
            
        except Exception as e:
            self.forensic.record_action(
                "metadata_extraction_error",
                f"Error extracting metadata from {file_path.name}: {str(e)}"
            )
            return None
    
    def _extract_date_from_filename(self, filename: str) -> Optional[str]:
        """
        Try to extract a date from the filename.

        Args:
            filename: Name of the file

        Returns:
            ISO format date string if found, None otherwise
        """
        # Common screenshot filename patterns
        patterns = [
            r'(\d{4})-(\d{2})-(\d{2})',  # YYYY-MM-DD
            r'(\d{2})/(\d{2})/(\d{4})',   # MM/DD/YYYY
        ]

        for pattern in patterns:
            match = re.search(pattern, filename)
            if match:
                try:
                    groups = match.groups()
                    if len(groups[0]) == 4:  # YYYY-MM-DD format
                        year, month, day = int(groups[0]), int(groups[1]), int(groups[2])
                    else:  # MM/DD/YYYY format
                        month, day, year = int(groups[0]), int(groups[1]), int(groups[2])
                    date = datetime(year, month, day)
                    return date.isoformat()
                except (ValueError, IndexError):
                    continue

        # YYYYMMDD_HHMMSS format (2 groups)
        match = re.search(r'(\d{4})(\d{2})(\d{2})_\d{6}', filename)
        if match:
            try:
                year, month, day = int(match.group(1)), int(match.group(2)), int(match.group(3))
                return datetime(year, month, day).isoformat()
            except ValueError:
                pass

        # Screenshot_YYYYMMDD format (1 group)
        match = re.search(r'Screenshot[_\s]+(\d{4})(\d{2})(\d{2})', filename)
        if match:
            try:
                year, month, day = int(match.group(1)), int(match.group(2)), int(match.group(3))
                return datetime(year, month, day).isoformat()
            except ValueError:
                pass

        # Standalone YYYYMMDD (only if surrounded by non-digits to avoid phone numbers)
        match = re.search(r'(?<!\d)(\d{4})(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])(?!\d)', filename)
        if match:
            try:
                year, month, day = int(match.group(1)), int(match.group(2)), int(match.group(3))
                if 1990 <= year <= 2099:
                    return datetime(year, month, day).isoformat()
            except ValueError:
                pass

        return None
    
    def validate_screenshots(self, screenshots: List[Dict]) -> Dict:
        """
        Validate extracted screenshots.
        
        Args:
            screenshots: List of screenshot metadata
            
        Returns:
            Validation report
        """
        report = {
            'total_files': len(screenshots),
            'valid_images': 0,
            'corrupt_images': 0,
            'missing_metadata': 0,
            'date_extracted': 0,
            'has_exif': 0,
            'issues': []
        }
        
        for screenshot in screenshots:
            # Check if image can be opened
            try:
                with Image.open(screenshot['path']) as img:
                    img.verify()
                report['valid_images'] += 1
            except Exception as e:
                report['corrupt_images'] += 1
                report['issues'].append(f"Corrupt image: {screenshot['filename']}")
            
            # Check metadata
            if not screenshot.get('image_metadata'):
                report['missing_metadata'] += 1
            elif screenshot['image_metadata'].get('exif'):
                report['has_exif'] += 1
            
            # Check date extraction
            if screenshot.get('extracted_date'):
                report['date_extracted'] += 1
        
        self.forensic.record_action(
            "screenshot_validation",
            f"Validated {report['total_files']} screenshots"
        )
        
        return report