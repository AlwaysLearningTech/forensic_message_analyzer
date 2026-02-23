#!/usr/bin/env python3
"""
Pre-run validation script — verifies fixes without spending $35.

Runs the FULL pipeline except AI analysis, then sends only 5 messages
to Claude to verify token counting works. Estimated cost: ~$0.01.

Usage:
    python3 validate_before_run.py              # Full validation with 5-message AI test
    python3 validate_before_run.py --no-ai      # Skip AI test entirely ($0 cost)
    python3 validate_before_run.py --estimate    # Just show extraction stats + cost estimate
"""

import sys
import json
import argparse
from pathlib import Path
from datetime import datetime

# Add src to path
sys.path.insert(0, str(Path(__file__).parent))

from src.config import Config
from src.forensic_utils import ForensicRecorder, ForensicIntegrity
from src.third_party_registry import ThirdPartyRegistry


def main():
    parser = argparse.ArgumentParser(description="Validate forensic analyzer before expensive AI run")
    parser.add_argument("--no-ai", action="store_true", help="Skip AI test entirely ($0 cost)")
    parser.add_argument("--estimate", action="store_true", help="Just show extraction stats + cost estimate")
    parser.add_argument("--ai-sample", type=int, default=5, help="Number of messages to send to AI (default: 5)")
    args = parser.parse_args()

    print("=" * 80)
    print(" FORENSIC MESSAGE ANALYZER — PRE-RUN VALIDATION")
    print("=" * 80)
    print(f"Started: {datetime.now()}")
    print()

    config = Config()
    passed = 0
    failed = 0
    warnings = 0

    # ---------------------------------------------------------------
    # Test 1: Config validation
    # ---------------------------------------------------------------
    print("[1/7] Config validation...")
    is_valid, errors = config.validate()
    blocking = [e for e in errors if "API key" not in e]
    if blocking:
        for e in blocking:
            print(f"  FAIL: {e}")
            failed += 1
    else:
        passed += 1
        print("  PASS")

    # ---------------------------------------------------------------
    # Test 2: Contact mappings
    # ---------------------------------------------------------------
    print("\n[2/7] Contact mappings...")
    mapped_names = set(config.contact_mappings.keys())
    print(f"  Mapped persons: {mapped_names}")
    for name, ids in config.contact_mappings.items():
        count = len(ids)
        print(f"    {name}: {count} identifier(s)")
        if count == 0:
            print(f"  WARN: {name} has zero identifiers — no messages will match")
            warnings += 1
    if len(mapped_names) > 0:
        passed += 1
        print("  PASS")
    else:
        print("  FAIL: No contact mappings configured")
        failed += 1

    # ---------------------------------------------------------------
    # Test 3: Data extraction
    # ---------------------------------------------------------------
    print("\n[3/7] Data extraction (reads local files — free)...")
    forensic = ForensicRecorder(Path(config.output_dir))
    integrity = ForensicIntegrity(forensic)
    third_party = ThirdPartyRegistry(forensic, config)

    from src.extractors.data_extractor import DataExtractor
    extractor = DataExtractor(forensic, third_party_registry=third_party)
    # extract_all() returns a list of message dicts directly
    messages = extractor.extract_all(
        start_date=config.start_date, end_date=config.end_date
    )
    print(f"  Total messages extracted: {len(messages):,}")

    # Show source breakdown
    sources = {}
    for m in messages:
        src = m.get('source', 'unknown')
        sources[src] = sources.get(src, 0) + 1
    for src, count in sorted(sources.items()):
        print(f"    {src}: {count:,}")

    if len(messages) == 0:
        print("  FAIL: No messages extracted")
        failed += 1
    else:
        passed += 1
        print("  PASS")

    # ---------------------------------------------------------------
    # Test 4: Mapped-contact filter
    # ---------------------------------------------------------------
    print("\n[4/7] Mapped-contact filter (AI analysis)...")
    ai_contacts = config.ai_contacts
    ai_specified = config.ai_contacts_specified
    if ai_specified:
        specified_names = ' & '.join(sorted(ai_specified))
        print(f"  AI analyzing: {config.person1_name} \u2194 {specified_names} conversations")
    else:
        print(f"  AI analyzing: all mapped-contact conversations")
    mapped_messages = [
        m for m in messages
        if m.get('sender') in ai_contacts and m.get('recipient') in ai_contacts
        and (ai_specified is None or m.get('sender') in ai_specified or m.get('recipient') in ai_specified)
    ]
    skipped = len(messages) - len(mapped_messages)
    print(f"  Total messages:  {len(messages):,}")
    print(f"  Mapped messages: {len(mapped_messages):,} (will be sent to AI)")
    print(f"  Skipped:         {skipped:,} (unmapped contacts — NOT sent to AI)")

    if len(mapped_messages) == 0:
        print("  FAIL: Zero messages match mapped contacts — check contact_mappings!")
        failed += 1
    elif len(mapped_messages) == len(messages):
        print("  WARN: Filter didn't reduce messages — all messages match? Check mapping.")
        warnings += 1
        passed += 1
    else:
        reduction = (skipped / len(messages)) * 100
        print(f"  Reduction: {reduction:.1f}%")
        passed += 1
        print("  PASS")

    # Show sender/recipient distribution for mapped messages
    sender_counts = {}
    for m in mapped_messages:
        s = m.get('sender', 'unknown')
        sender_counts[s] = sender_counts.get(s, 0) + 1
    print(f"\n  Sender distribution (mapped messages):")
    for s, c in sorted(sender_counts.items(), key=lambda x: -x[1])[:10]:
        print(f"    {s}: {c:,}")

    # ---------------------------------------------------------------
    # Test 5: Non-AI analysis phases (free)
    # ---------------------------------------------------------------
    print("\n[5/7] Non-AI analysis phases (timezone handling test)...")
    import pandas as pd
    try:
        combined_df = pd.DataFrame(messages)

        from src.analyzers.threat_analyzer import ThreatAnalyzer
        ta = ThreatAnalyzer(forensic)
        threat_results = ta.detect_threats(combined_df)
        print(f"  ThreatAnalyzer: PASS ({len(threat_results)} results)")

        from src.analyzers.sentiment_analyzer import SentimentAnalyzer
        sa = SentimentAnalyzer(forensic)
        sentiment_results = sa.analyze_sentiment(combined_df)
        print(f"  SentimentAnalyzer: PASS ({len(sentiment_results)} results)")

        from src.analyzers.yaml_pattern_analyzer import YamlPatternAnalyzer
        pa = YamlPatternAnalyzer(forensic)
        pattern_results = pa.analyze_patterns(combined_df)
        print(f"  YamlPatternAnalyzer: PASS ({len(pattern_results)} results)")

        from src.analyzers.communication_metrics import CommunicationMetricsAnalyzer
        cm = CommunicationMetricsAnalyzer()
        metrics = cm.analyze_messages(messages)
        print(f"  CommunicationMetrics: PASS")

        from src.analyzers.behavioral_analyzer import BehavioralAnalyzer
        ba = BehavioralAnalyzer(forensic)
        behavioral = ba.analyze_patterns(combined_df)
        print(f"  BehavioralAnalyzer: PASS")

        passed += 1
        print("  ALL NON-AI PHASES PASS")
    except Exception as e:
        print(f"  FAIL: {e}")
        import traceback
        traceback.print_exc()
        failed += 1

    # ---------------------------------------------------------------
    # Test 6: Cost estimate for full AI run
    # ---------------------------------------------------------------
    print("\n[6/7] Cost estimate for full AI run...")
    try:
        from src.analyzers.ai_analyzer import AIAnalyzer
        ai = AIAnalyzer(forensic_recorder=forensic)

        batch_size = getattr(config, 'batch_size', 50)
        num_batches = (len(mapped_messages) + batch_size - 1) // batch_size

        # Estimate input tokens: system prompt per batch + message content
        system_tokens = ai._estimate_tokens(ai._SYSTEM_PROMPT) * num_batches
        message_tokens = 0
        for i in range(0, len(mapped_messages), batch_size):
            batch = mapped_messages[i:i + batch_size]
            batch_text = ai._prepare_batch(batch)
            message_tokens += ai._estimate_tokens(batch_text)
        est_input = system_tokens + message_tokens
        # Based on actual run data: avg ~1,600 output tokens per batch
        # (previous estimate of 385 was from billing aggregates that didn't match per-request data)
        est_output = num_batches * 1600

        # Batch API rates for Opus 4.6: $2.50/MTok input, $12.50/MTok output
        est_cost = (est_input / 1_000_000) * 2.50 + (est_output / 1_000_000) * 12.50

        # With caching (system prompt only counted once at full price)
        # Cache reads = $0.25/MTok (10% of batch input rate)
        cache_savings = (system_tokens - ai._estimate_tokens(ai._SYSTEM_PROMPT)) * (2.50 - 0.25) / 1_000_000
        est_cost_cached = est_cost - cache_savings

        # Per-component breakdown
        input_cost = (est_input / 1_000_000) * 2.50
        output_cost = (est_output / 1_000_000) * 12.50

        print(f"  Messages to analyze: {len(mapped_messages):,}")
        print(f"  Batch size: {batch_size}")
        print(f"  Number of batches: {num_batches}")
        print(f"  Estimated input tokens:  ~{est_input:,}  (${input_cost:.2f})")
        print(f"  Estimated output tokens: ~{est_output:,}  (${output_cost:.2f})")
        print(f"  Estimated cost (no cache): ~${est_cost:.2f}")
        print(f"  Estimated cost (with cache): ~${est_cost_cached:.2f}")
        print()

        if est_cost > 50:
            print(f"  WARNING: Estimated cost > $50! Consider reducing batch size or message count.")
            warnings += 1
        elif est_cost > 20:
            print(f"  CAUTION: Estimated cost > $20.")
            warnings += 1

        passed += 1
        print("  PASS")
    except Exception as e:
        print(f"  FAIL: {e}")
        import traceback
        traceback.print_exc()
        failed += 1

    # ---------------------------------------------------------------
    # Test 7: Tiny AI test (5 messages — ~$0.01)
    # ---------------------------------------------------------------
    if args.no_ai or args.estimate:
        print(f"\n[7/7] AI test: SKIPPED (--no-ai or --estimate flag)")
    else:
        sample_size = args.ai_sample
        print(f"\n[7/7] AI test ({sample_size} messages — ~$0.01)...")
        try:
            from src.analyzers.ai_analyzer import AIAnalyzer
            ai_test = AIAnalyzer(forensic_recorder=forensic)

            if not ai_test.client:
                print("  SKIP: No API key configured")
                warnings += 1
            else:
                # Use synchronous mode for tiny test (no batch API overhead)
                ai_test.use_batch_api = False
                sample = mapped_messages[:sample_size]
                print(f"  Sending {len(sample)} messages via synchronous API...")

                results = ai_test.analyze_messages(sample, batch_size=sample_size)
                stats = results.get('processing_stats', {})
                input_tok = stats.get('input_tokens', 0)
                output_tok = stats.get('output_tokens', 0)
                total_tok = input_tok + output_tok
                errors = stats.get('errors', [])

                print(f"  Tokens used: {input_tok:,} input + {output_tok:,} output = {total_tok:,} total")
                if total_tok == 0:
                    print("  FAIL: Token counting returned 0 — still broken!")
                    failed += 1
                else:
                    # Synchronous standard rates for Opus 4.6: $5/MTok input, $25/MTok output
                    actual_cost = (input_tok / 1_000_000) * 5.0 + (output_tok / 1_000_000) * 25.0
                    print(f"  Actual cost: ~${actual_cost:.4f} (synchronous rates)")
                    passed += 1
                    print("  PASS")

                if errors:
                    print(f"  Errors: {errors}")
                    warnings += len(errors)
        except Exception as e:
            print(f"  FAIL: {e}")
            import traceback
            traceback.print_exc()
            failed += 1

    # ---------------------------------------------------------------
    # Summary
    # ---------------------------------------------------------------
    print("\n" + "=" * 80)
    print(f" VALIDATION SUMMARY: {passed} passed, {failed} failed, {warnings} warnings")
    print("=" * 80)

    if failed > 0:
        print("\nDO NOT run the full analysis until failures are resolved.")
        sys.exit(1)
    elif warnings > 0:
        print("\nPassed with warnings. Review above before running full analysis.")
        print("Run full analysis: python3 run.py")
        sys.exit(0)
    else:
        print("\nAll checks passed! Safe to run full analysis.")
        print("Run full analysis: python3 run.py")
        sys.exit(0)


if __name__ == "__main__":
    main()
