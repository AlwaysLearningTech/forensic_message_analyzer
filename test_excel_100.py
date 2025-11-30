#!/usr/bin/env python3
"""
Test Excel generation with actual data but limited to 100 messages.
"""

import json
from pathlib import Path
import sys
import os

# Add src to path and set proper module structure
os.chdir(Path(__file__).parent)
sys.path.insert(0, str(Path(__file__).parent))

from src.forensic_utils import ForensicRecorder
from src.reporters.excel_reporter import ExcelReporter

# Load actual data
print("Loading extracted data...")
data_file = max(Path("~/workspace/output/forensic_message_analyzer").expanduser().glob("extracted_data_*.json"), 
                key=lambda x: x.stat().st_mtime)
with open(data_file) as f:
    extracted_data = json.load(f)

print(f"Loaded {len(extracted_data['messages'])} messages")

# Load analysis results
print("Loading analysis results...")
results_file = max(Path("~/workspace/output/forensic_message_analyzer").expanduser().glob("analysis_results_*.json"), 
                   key=lambda x: x.stat().st_mtime)
with open(results_file) as f:
    analysis_results = json.load(f)

# Load review decisions
print("Loading review decisions...")
review_file = Path("~/workspace/data/forensic_message_analyzer/review/manual_reviews.json").expanduser()
if review_file.exists():
    with open(review_file) as f:
        review_data = json.load(f)
        review_decisions = {
            'total_reviewed': len(review_data.get('reviews', [])),
            'relevant': sum(1 for r in review_data.get('reviews', []) if r.get('decision') == 'relevant'),
            'reviews': review_data.get('reviews', [])
        }
else:
    review_decisions = {'total_reviewed': 0, 'relevant': 0, 'reviews': []}

# LIMIT TO FIRST 100 MESSAGES FOR TESTING
print("\n** LIMITING TO FIRST 100 MESSAGES FOR TESTING **\n")
extracted_data['messages'] = extracted_data['messages'][:100]

# Create reporter and generate
print("Creating Excel report...")
recorder = ForensicRecorder()
reporter = ExcelReporter(recorder)

output_path = Path("~/workspace/output/forensic_message_analyzer/test_100_messages.xlsx").expanduser()
result = reporter.generate_report(extracted_data, analysis_results, review_decisions, output_path)

print(f"\n✓ Success! Report generated: {result}")
print(f"  File size: {result.stat().st_size} bytes")
