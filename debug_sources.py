#!/usr/bin/env python3
"""Show filtered message counts by source and sender to diagnose ratio issues."""
import sys
from pathlib import Path
from collections import Counter
sys.path.insert(0, str(Path(__file__).parent))

from src.config import Config
from src.forensic_utils import ForensicRecorder
from src.third_party_registry import ThirdPartyRegistry
from src.extractors.data_extractor import DataExtractor

config = Config()
forensic = ForensicRecorder(Path(config.output_dir))
tp = ThirdPartyRegistry(forensic, config)
extractor = DataExtractor(forensic, third_party_registry=tp)
messages = extractor.extract_all()

ai_contacts = config.ai_contacts
ai_specified = config.ai_contacts_specified
filtered = [
    m for m in messages
    if m.get('sender') in ai_contacts and m.get('recipient') in ai_contacts
    and (ai_specified is None or m.get('sender') in ai_specified or m.get('recipient') in ai_specified)
]

print("=== FILTERED MESSAGES BY SOURCE + SENDER ===")
by_source = {}
for m in filtered:
    src = m.get('source', 'unknown')
    sender = m.get('sender', 'unknown')
    key = (src, sender)
    by_source[key] = by_source.get(key, 0) + 1

for (src, sender), cnt in sorted(by_source.items(), key=lambda x: (-x[1])):
    print(f"  {src:12s}  {sender:20s}  {cnt:,}")

print()
print("=== TOTALS BY SOURCE ===")
src_totals = Counter(m.get('source') for m in filtered)
for src, cnt in src_totals.most_common():
    print(f"  {src}: {cnt:,}")

print()
print("=== ALL MESSAGES (UNFILTERED) BY SOURCE + SENDER (top 20) ===")
all_by = {}
for m in messages:
    src = m.get('source', 'unknown')
    sender = m.get('sender', 'unknown')
    key = (src, sender)
    all_by[key] = all_by.get(key, 0) + 1

for i, ((src, sender), cnt) in enumerate(sorted(all_by.items(), key=lambda x: (-x[1]))):
    if i >= 20:
        break
    print(f"  {src:12s}  {sender:20s}  {cnt:,}")
