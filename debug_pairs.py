#!/usr/bin/env python3
"""Quick check: who are the recipients of David Snyder messages?"""
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

ai = config.ai_contacts
filtered = [m for m in messages if m.get('sender') in ai and m.get('recipient') in ai]

# Show sender->recipient pairs
pairs = Counter((m.get('sender'), m.get('recipient')) for m in filtered)
print(f"AI contacts: {ai}")
print(f"Filtered messages: {len(filtered):,}")
print()
for (s, r), c in pairs.most_common(20):
    print(f"  {s} -> {r}: {c:,}")

# What sources do "David Snyder -> Me" messages come from?
ds_me = [m for m in filtered if m.get('sender') == 'David Snyder' and m.get('recipient') == 'Me']
sources = Counter(m.get('source', 'unknown') for m in ds_me)
print(f"\n'David Snyder -> Me' by source ({len(ds_me):,} total):")
for src, cnt in sources.most_common():
    print(f"  {src}: {cnt:,}")

# Who are the actual conversation partners for these messages?
# Check if there's a chat/thread/group field that reveals the actual conversation
if ds_me:
    sample = ds_me[0]
    print(f"\nSample 'David Snyder -> Me' message keys: {list(sample.keys())}")
    # Show a few samples
    for m in ds_me[:3]:
        print(f"  src={m.get('source')} sender={m.get('sender')} recip={m.get('recipient')} chat={m.get('chat_id', m.get('thread_id', m.get('conversation_id', 'N/A')))}")
