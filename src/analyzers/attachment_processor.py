"""
Attachment processing module.
Catalogs and analyzes media attachments from messages.
"""

import logging
import hashlib
from pathlib import Path
from typing import List, Dict, Any
from datetime import datetime
import mimetypes
from PIL import Image
import magic  # python-magic library

class AttachmentProcessor:
    """Process and catalog message attachments."""
    
    def __init__(self, forensic):
        """Initialize attachment processor."""
        self.forensic = forensic
        self.logger = logging.getLogger(__name__)
        self.processed_attachments = []
        
        self.forensic.record_action(
            "ATTACHMENT_PROCESSOR_INIT",
            "Initialized attachment processor"
        )
    
    def process_attachments(self, attachment_dir: Path = None) -> List[Dict[str, Any]]:
        """
        Process all attachments in the specified directory.
        
        Args:
            attachment_dir: Directory containing attachments
            
        Returns:
            List of processed attachment metadata
        """
        if attachment_dir is None:
            attachment_dir = Path("source_files/attachments")
        
        if not attachment_dir.exists():
            self.logger.warning(f"Attachment directory not found: {attachment_dir}")
            return []
        
        attachments = []
        
        for file_path in attachment_dir.rglob('*'):
            if file_path.is_file():
                try:
                    attachment_data = self.process_single_attachment(file_path)
                    attachments.append(attachment_data)
                except Exception as e:
                    self.logger.error(f"Failed to process {file_path}: {e}")
        
        self.logger.info(f"Processed {len(attachments)} attachments")
        
        self.forensic.record_action(
            "ATTACHMENTS_PROCESSED",
            f"Processed {len(attachments)} media files"
        )
        
        return attachments
    
    def process_single_attachment(self, file_path: Path) -> Dict[str, Any]:
        """
        Process a single attachment file.
        
        Args:
            file_path: Path to the attachment
            
        Returns:
            Dictionary of attachment metadata
        """
        # Calculate file hash
        with open(file_path, 'rb') as f:
            file_hash = hashlib.sha256(f.read()).hexdigest()
        
        # Get file metadata
        stat = file_path.stat()
        
        # Determine MIME type
        mime = magic.Magic(mime=True)
        mime_type = mime.from_file(str(file_path))
        
        attachment_data = {
            'filename': file_path.name,
            'filepath': str(file_path),
            'file_hash': file_hash,
            'size_bytes': stat.st_size,
            'mime_type': mime_type,
            'created': datetime.fromtimestamp(stat.st_ctime).isoformat(),
            'modified': datetime.fromtimestamp(stat.st_mtime).isoformat(),
            'type': self.categorize_file_type(mime_type),
            'metadata': {}
        }
        
        # Extract additional metadata based on file type
        if attachment_data['type'] == 'image':
            attachment_data['metadata'] = self.extract_image_metadata(file_path)
        elif attachment_data['type'] == 'video':
            attachment_data['metadata'] = self.extract_video_metadata(file_path)
        elif attachment_data['type'] == 'audio':
            attachment_data['metadata'] = self.extract_audio_metadata(file_path)
        
        self.forensic.record_action(
            "ATTACHMENT_CATALOGED",
            f"Cataloged {file_path.name}: {mime_type}, {stat.st_size} bytes"
        )
        
        return attachment_data
    
    def categorize_file_type(self, mime_type: str) -> str:
        """Categorize file based on MIME type."""
        if mime_type.startswith('image/'):
            return 'image'
        elif mime_type.startswith('video/'):
            return 'video'
        elif mime_type.startswith('audio/'):
            return 'audio'
        elif mime_type.startswith('text/'):
            return 'text'
        elif 'pdf' in mime_type:
            return 'document'
        else:
            return 'other'
    
    def extract_image_metadata(self, file_path: Path) -> Dict[str, Any]:
        """Extract metadata from image files."""
        try:
            with Image.open(file_path) as img:
                metadata = {
                    'width': img.width,
                    'height': img.height,
                    'format': img.format,
                    'mode': img.mode
                }
                
                # Extract EXIF data if available
                if hasattr(img, '_getexif'):
                    exif = img._getexif()
                    if exif:
                        metadata['exif'] = {k: v for k, v in exif.items() 
                                           if isinstance(v, (str, int, float))}
                
                return metadata
        except Exception as e:
            self.logger.error(f"Failed to extract image metadata: {e}")
            return {}
    
    def extract_video_metadata(self, file_path: Path) -> Dict[str, Any]:
        """Extract metadata from video files."""
        # Basic metadata - could be enhanced with ffmpeg-python
        return {
            'duration': 'unknown',
            'codec': 'unknown'
        }
    
    def extract_audio_metadata(self, file_path: Path) -> Dict[str, Any]:
        """Extract metadata from audio files."""
        # Basic metadata - could be enhanced with mutagen
        return {
            'duration': 'unknown',
            'bitrate': 'unknown'
        }
    
    def generate_attachment_summary(self, attachments: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate summary statistics for attachments."""
        if not attachments:
            return {}
        
        summary = {
            'total_attachments': len(attachments),
            'total_size_bytes': sum(a['size_bytes'] for a in attachments),
            'types': {},
            'mime_types': {},
            'largest_file': max(attachments, key=lambda x: x['size_bytes'])['filename'],
            'oldest_file': min(attachments, key=lambda x: x['created'])['filename']
        }
        
        for attachment in attachments:
            file_type = attachment['type']
            summary['types'][file_type] = summary['types'].get(file_type, 0) + 1
            
            mime_type = attachment['mime_type']
            summary['mime_types'][mime_type] = summary['mime_types'].get(mime_type, 0) + 1
        
        return summary