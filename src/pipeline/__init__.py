"""Per-phase runners extracted from ForensicAnalyzer.

Each phase is a single module exporting one function that takes the ForensicAnalyzer instance as ``analyzer`` plus whatever the original method took. ForensicAnalyzer keeps thin method wrappers so existing callers and tests are unaffected; the phase logic lives here, one file per phase, so changes to any single phase touch one file instead of the 1400-line orchestrator.

All phases share state through the analyzer: config, forensic, integrity, manifest, evidence, third_party_registry, and the run-specific path attributes (_extracted_data_path, _analysis_results_path, _review_session_id). The analyzer remains the single source of truth for mutable pipeline state.
"""
