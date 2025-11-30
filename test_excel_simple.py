#!/usr/bin/env python3
"""
Simple test of Excel row-by-row writing with just 10 messages.
"""

import xlsxwriter
from pathlib import Path

# Create test workbook
output_path = Path("~/workspace/output/forensic_message_analyzer/test_simple.xlsx").expanduser()
print(f"Creating test Excel: {output_path}")

workbook = xlsxwriter.Workbook(str(output_path))

# Create test data - just 10 messages
test_messages = [
    {'timestamp': '2025-01-01 10:00:00', 'sender': 'Me', 'recipient': 'Person1', 'content': 'Test message 1', 'source': 'iMessage'},
    {'timestamp': '2025-01-01 10:01:00', 'sender': 'Person1', 'recipient': 'Me', 'content': 'Test reply 1', 'source': 'iMessage'},
    {'timestamp': '2025-01-01 10:02:00', 'sender': 'Me', 'recipient': 'Person1', 'content': 'Test message 2', 'source': 'iMessage'},
    {'timestamp': '2025-01-01 10:03:00', 'sender': 'Person1', 'recipient': 'Me', 'content': 'Test reply 2', 'source': 'iMessage'},
    {'timestamp': '2025-01-01 10:04:00', 'sender': 'Me', 'recipient': 'Person2', 'content': 'Test message 3', 'source': 'WhatsApp'},
    {'timestamp': '2025-01-01 10:05:00', 'sender': 'Person2', 'recipient': 'Me', 'content': 'Test reply 3', 'source': 'WhatsApp'},
    {'timestamp': '2025-01-01 10:06:00', 'sender': 'Me', 'recipient': 'Person1', 'content': 'Test message 4', 'source': 'iMessage'},
    {'timestamp': '2025-01-01 10:07:00', 'sender': 'Person1', 'recipient': 'Me', 'content': 'Test reply 4', 'source': 'iMessage'},
    {'timestamp': '2025-01-01 10:08:00', 'sender': 'Me', 'recipient': 'Person2', 'content': 'Test message 5', 'source': 'WhatsApp'},
    {'timestamp': '2025-01-01 10:09:00', 'sender': 'Person2', 'recipient': 'Me', 'content': 'Test reply 5', 'source': 'WhatsApp'},
]

print(f"Writing {len(test_messages)} test messages...")

# Create worksheet
worksheet = workbook.add_worksheet('Test Messages')

# Get columns from first message
columns = ['timestamp', 'sender', 'recipient', 'content', 'source']

# Write header
print("Writing header...")
for col_num, col_name in enumerate(columns):
    worksheet.write(0, col_num, col_name)

# Write rows
print("Writing rows...")
for row_num, msg in enumerate(test_messages, start=1):
    for col_num, col_name in enumerate(columns):
        value = msg.get(col_name, '')
        worksheet.write(row_num, col_num, value)
    print(f"  Row {row_num} written")

# Close workbook
print("Closing workbook...")
workbook.close()

print(f"✓ Success! File created: {output_path}")
print(f"  File size: {output_path.stat().st_size} bytes")
