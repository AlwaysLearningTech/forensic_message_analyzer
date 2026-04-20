"""
Attachment processing module.
Catalogs and analyzes media attachments from messages.
"""

import logging
import hashlib
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime
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
        # Calculate file hash (chunked to handle large files)
        sha256 = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                sha256.update(chunk)
        file_hash = sha256.hexdigest()
        
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
    
    # EXIF tag numbers worth surfacing in plain language. Geolocation (GPSInfo=34853) is surfaced separately because its presence is itself a forensic signal — attackers often don't realize photos leak location. See Pillow's ExifTags module and EXIF 2.32 spec.
    _EXIF_TAG_NAMES = {
        271: "Make",
        272: "Model",
        274: "Orientation",
        305: "Software",
        306: "DateTime",
        315: "Artist",
        33432: "Copyright",
        34665: "ExifOffset",
        34853: "GPSInfo",
        36867: "DateTimeOriginal",
        36868: "DateTimeDigitized",
        37510: "UserComment",
        40965: "InteropOffset",
        41728: "FileSource",
        41729: "SceneType",
        42016: "ImageUniqueID",
        42032: "CameraOwnerName",
        42033: "BodySerialNumber",
        42034: "LensSpecification",
        42036: "LensModel",
        42037: "LensSerialNumber",
    }

    @staticmethod
    def _convert_gps_to_degrees(value) -> Optional[float]:
        """Convert EXIF GPS rational tuple (deg, min, sec) to decimal degrees."""
        try:
            d, m, s = value
            d = float(getattr(d, "real", d))
            m = float(getattr(m, "real", m))
            s = float(getattr(s, "real", s))
            return d + (m / 60.0) + (s / 3600.0)
        except (TypeError, ValueError):
            return None

    def extract_image_metadata(self, file_path: Path) -> Dict[str, Any]:
        """Extract forensic metadata from image files.

        Captures EXIF tags under their human-readable names, extracts and decodes any GPS coordinates, and surfaces a small set of tamper indicators (e.g. presence of an editing Software tag, DateTimeDigitized earlier than DateTimeOriginal). The returned dict includes an 'anomalies' list that reports and reviewers can surface.
        """
        try:
            with Image.open(file_path) as img:
                metadata = {
                    'width': img.width,
                    'height': img.height,
                    'format': img.format,
                    'mode': img.mode,
                    'exif': {},
                    'gps': None,
                    'anomalies': [],
                }

                exif = img.getexif()
                if exif:
                    for tag_id, value in exif.items():
                        name = self._EXIF_TAG_NAMES.get(tag_id, f"Tag_{tag_id}")
                        if isinstance(value, (str, int, float)):
                            metadata['exif'][name] = value
                        elif isinstance(value, bytes):
                            try:
                                metadata['exif'][name] = value.decode('utf-8', errors='replace')
                            except Exception:
                                metadata['exif'][name] = repr(value)

                    # Decode GPSInfo IFD if present. Pillow exposes it via get_ifd(ExifTags.IFD.GPSInfo).
                    try:
                        from PIL import ExifTags as _ExifTags
                        gps_ifd = exif.get_ifd(_ExifTags.IFD.GPSInfo) if hasattr(exif, "get_ifd") else {}
                    except Exception:
                        gps_ifd = {}
                    if gps_ifd:
                        lat = self._convert_gps_to_degrees(gps_ifd.get(2))
                        lat_ref = gps_ifd.get(1, 'N')
                        lon = self._convert_gps_to_degrees(gps_ifd.get(4))
                        lon_ref = gps_ifd.get(3, 'E')
                        if lat is not None and lon is not None:
                            if lat_ref in ('S', b'S'):
                                lat = -lat
                            if lon_ref in ('W', b'W'):
                                lon = -lon
                            metadata['gps'] = {
                                'latitude': lat,
                                'longitude': lon,
                                'altitude': float(gps_ifd.get(6)) if gps_ifd.get(6) is not None else None,
                                'timestamp': str(gps_ifd.get(29)) if gps_ifd.get(29) else None,
                            }
                            metadata['anomalies'].append("geolocation_present")

                # Tamper / edit indicators. A photo that has been through Photoshop or a mobile edit app typically carries a Software tag; a mismatch between DateTimeOriginal and DateTimeDigitized is another signal.
                software = metadata['exif'].get('Software', '')
                if software and any(tool in str(software).lower() for tool in ("photoshop", "gimp", "lightroom", "affinity", "pixelmator")):
                    metadata['anomalies'].append(f"edited_by:{software}")
                dto = metadata['exif'].get('DateTimeOriginal')
                dtd = metadata['exif'].get('DateTimeDigitized')
                if dto and dtd and dto != dtd:
                    metadata['anomalies'].append("datetime_mismatch")
                if not metadata['exif']:
                    metadata['anomalies'].append("exif_stripped")

                return metadata
        except Exception as e:
            self.logger.error(f"Failed to extract image metadata: {e}")
            return {'anomalies': [f"read_error:{type(e).__name__}"]}
    
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