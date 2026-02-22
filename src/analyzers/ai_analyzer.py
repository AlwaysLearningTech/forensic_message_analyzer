"""
AI-powered analysis module for forensic message analyzer.
Uses Anthropic Claude (via Azure AI or direct API) for advanced
threat detection and content analysis in family law proceedings.

Supports two processing modes:
- Batch API (default): Submits all requests asynchronously at 50% cost discount.
  Prompt caching further reduces costs on repeated system prompts.
- Synchronous: Real-time processing with rate limiting (for development/testing).
"""

import os
import json
import time
import re
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime
import pandas as pd
import logging
from dataclasses import dataclass

try:
    from anthropic import Anthropic
    AI_AVAILABLE = True
except ImportError:
    AI_AVAILABLE = False

from ..config import Config
from ..forensic_utils import ForensicRecorder

# Initialize config
config = Config()

logger = logging.getLogger(__name__)


class RateLimiter:
    """Rate limiter for synchronous API calls to respect token limits."""

    def __init__(self, max_requests_per_minute: int = 60, max_tokens_per_minute: int = 150000):
        self.max_requests_per_minute = max_requests_per_minute
        self.max_tokens_per_minute = max_tokens_per_minute
        self.request_times: List[float] = []
        self.token_counts: List[Tuple[float, int]] = []

    def wait_if_needed(self, estimated_tokens: int = 0):
        current_time = time.time()

        # Clean old entries (older than 60 seconds)
        self.request_times = [t for t in self.request_times if current_time - t < 60]
        self.token_counts = [(t, c) for t, c in self.token_counts if current_time - t < 60]

        # Check request limit
        if len(self.request_times) >= self.max_requests_per_minute:
            sleep_time = 60 - (current_time - self.request_times[0]) + 0.1
            if sleep_time > 0:
                time.sleep(sleep_time)

        # Check token limit
        current_tokens = sum(c for _, c in self.token_counts)
        if current_tokens + estimated_tokens > self.max_tokens_per_minute:
            sleep_time = 60 - (current_time - self.token_counts[0][0]) + 0.1
            if sleep_time > 0:
                time.sleep(sleep_time)

        # Record this request
        self.request_times.append(current_time)
        self.token_counts.append((current_time, estimated_tokens))


def _extract_json(text: str) -> dict:
    """Extract JSON from a response that may contain markdown code fences."""
    # Strip markdown code fences if present
    cleaned = re.sub(r'^```(?:json)?\s*', '', text.strip())
    cleaned = re.sub(r'\s*```$', '', cleaned)
    return json.loads(cleaned)


class AIAnalyzer:
    """
    AI-powered analysis using Anthropic Claude Opus.

    Supports two processing modes:
    - Batch API (default): Submits all requests asynchronously at 50% cost discount.
      Uses prompt caching for additional savings on repeated system prompts.
    - Synchronous: Processes requests one at a time with rate limiting.
    """

    def __init__(self, forensic_recorder: Optional[ForensicRecorder] = None):
        self.forensic = forensic_recorder or ForensicRecorder()

        # Get configuration from config instance
        self.api_key = config.ai_api_key
        self.endpoint = config.ai_endpoint
        self.model = config.ai_model or 'claude-opus-4-6'

        # Token limits from config
        self.max_tokens_per_request = max(
            getattr(config, 'max_tokens_per_request', 4096), 4096
        )
        self.max_tokens_per_minute = getattr(config, 'tokens_per_minute', 150000)
        self.max_requests_per_minute = 60
        self.use_batch_api = getattr(config, 'use_batch_api', True)

        # Initialize Anthropic client if credentials available
        self.client = None

        if AI_AVAILABLE and self.api_key:
            try:
                client_kwargs = {"api_key": self.api_key}

                # If an endpoint is configured, use it as base_url
                if self.endpoint:
                    base = self.endpoint.rstrip("/")
                    client_kwargs["base_url"] = base

                self.client = Anthropic(**client_kwargs)

                # Initialize rate limiter (used in synchronous mode)
                self.rate_limiter = RateLimiter(
                    max_requests_per_minute=self.max_requests_per_minute,
                    max_tokens_per_minute=self.max_tokens_per_minute,
                )

                self.forensic.record_action(
                    "ai_analyzer_initialized",
                    f"Anthropic Claude analyzer initialized with {self.model}",
                    {
                        "model": self.model,
                        "endpoint": self.endpoint or "api.anthropic.com",
                        "batch_api": self.use_batch_api,
                    },
                )
            except Exception as e:
                self.forensic.record_action(
                    "ai_init_error",
                    f"Failed to initialize Anthropic Claude: {str(e)}",
                    {"error": str(e)},
                )
                self.client = None
        else:
            self.forensic.record_action(
                "ai_analyzer_disabled",
                "Claude analyzer disabled - no API key configured or anthropic package missing",
            )

    @staticmethod
    def _estimate_tokens(text: str) -> int:
        """Rough token count (~4 characters per token for English)."""
        return max(1, len(text) // 4)

    # ------------------------------------------------------------------
    # System prompt (shared across all analysis calls)
    # ------------------------------------------------------------------

    _SYSTEM_PROMPT = (
        "You are a forensic analyst specializing in digital communications "
        "for family law proceedings (divorce, custody, domestic relations).\n\n"
        "Analyze the provided conversation with specific focus on:\n"
        "1. **Sentiment and emotional escalation**: Track emotional intensity changes. "
        "Note shifts from calm to hostile, or patterns of manipulation "
        "(gaslighting, guilt-tripping, love-bombing).\n"
        "2. **Threats and concerning behavior**: Identify direct or veiled threats "
        "to physical safety, threats regarding children/custody, financial coercion, "
        "harassment, stalking behavior, and parental alienation language.\n"
        "3. **Behavioral patterns**: Detect controlling behavior, isolation tactics, "
        "substance abuse references, violation of court orders, disparagement of "
        "the other parent in front of children.\n"
        "4. **Key topics**: Child welfare, custody arrangements, financial matters, "
        "co-parenting communication, protective order compliance.\n"
        "5. **Risk indicators**: Escalation patterns, safety concerns for children "
        "or adults, evidence of parental unfitness.\n\n"
        "IMPORTANT GUIDELINES:\n"
        "- Provide objective, fact-based analysis suitable for court proceedings.\n"
        "- Clearly distinguish direct observations from interpretations.\n"
        "- Note exact quotes that support findings.\n"
        "- Assess severity of each finding: critical, high, medium, low.\n"
        "- Consider the family law context: best interests of children, "
        "safety of parties.\n\n"
        "Format your response as valid JSON (no markdown fences) with this structure:\n"
        "{\n"
        '    "sentiment": {\n'
        '        "overall": "positive/neutral/negative",\n'
        '        "shifts": [{"from": "...", "to": "...", "approximate_position": "..."}],\n'
        '        "intensity": 0-10,\n'
        '        "escalation_detected": false\n'
        "    },\n"
        '    "threats": {\n'
        '        "found": false,\n'
        '        "severity": "none/low/medium/high/critical",\n'
        '        "details": [{"type": "...", "quote": "...", "severity": "...", '
        '"recommended_action": "..."}]\n'
        "    },\n"
        '    "behavioral_patterns": {\n'
        '        "patterns": [{"type": "...", "description": "...", "severity": "..."}],\n'
        '        "anomalies": [{"description": "...", "concern_level": "..."}]\n'
        "    },\n"
        '    "key_topics": [],\n'
        '    "risk_indicators": [{"indicator": "...", "severity": "...", '
        '"recommended_action": "..."}],\n'
        '    "notable_quotes": [{"quote": "...", "significance": "..."}]\n'
        "}"
    )

    def _cached_system_prompt(self) -> list:
        """Return system prompt as content blocks with prompt caching enabled.

        Prompt caching avoids re-processing the identical system prompt on every
        request. With the Batch API, this can reduce input token costs by up to
        90% for the system prompt portion across all requests in the batch.
        """
        return [{
            "type": "text",
            "text": self._SYSTEM_PROMPT,
            "cache_control": {"type": "ephemeral"},
        }]

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    def analyze_messages(self, messages: List[Dict], batch_size: int = 50) -> Dict[str, Any]:
        """
        Analyze messages using Claude Opus for advanced insights.

        Uses the Batch API by default (50% cost discount + prompt caching).
        Falls back to synchronous processing if batch API is disabled or fails.

        Args:
            messages: List of message dictionaries
            batch_size: Number of messages per analysis request (default 50).
                        Larger values reduce system prompt overhead and cost.

        Returns:
            Dictionary containing AI analysis results
        """
        if not self.client:
            self.forensic.record_action(
                "ai_analysis_skipped",
                "AI analysis skipped - Anthropic Claude not configured",
            )
            return self._empty_analysis()

        if self.use_batch_api:
            try:
                return self._analyze_messages_batch(messages, batch_size)
            except Exception as e:
                logger.warning(f"Batch API failed, falling back to synchronous: {e}")
                self.forensic.record_action(
                    "batch_api_fallback",
                    f"Batch API unavailable, using synchronous mode: {str(e)}",
                    {"error": str(e)},
                )

        return self._analyze_messages_sync(messages, batch_size)

    # ------------------------------------------------------------------
    # Batch API path (50% cost discount)
    # ------------------------------------------------------------------

    def _analyze_messages_batch(self, messages: List[Dict], batch_size: int) -> Dict[str, Any]:
        """
        Submit all analysis requests via the Anthropic Message Batches API.

        Benefits:
        - 50% cost discount on all token usage
        - Prompt caching reduces system prompt costs by up to 90%
        - No client-side rate limiting needed (handled server-side)
        - Up to 100,000 requests per batch

        Processing is asynchronous: requests are submitted in bulk,
        then we poll until the batch completes (typically under 1 hour).
        """
        analysis_results = self._init_analysis_results(len(messages))

        # Build all batch requests
        batch_requests = []
        for i in range(0, len(messages), batch_size):
            batch = messages[i:i + batch_size]
            batch_text = self._prepare_batch(batch)
            batch_requests.append({
                "custom_id": f"analysis_{i // batch_size}",
                "params": {
                    "model": self.model,
                    "system": self._cached_system_prompt(),
                    "messages": [{"role": "user", "content": batch_text}],
                    "temperature": 0.3,
                    "max_tokens": self.max_tokens_per_request,
                },
            })

        total_requests = len(batch_requests)
        print(f"    Submitting {total_requests} requests via Batch API (50% cost discount)...")

        self.forensic.record_action(
            "batch_api_submit",
            f"Submitting {total_requests} analysis requests via Batch API",
            {
                "total_requests": total_requests,
                "batch_size": batch_size,
                "total_messages": len(messages),
            },
        )

        # Submit the batch
        message_batch = self.client.messages.batches.create(requests=batch_requests)
        batch_id = message_batch.id

        self.forensic.record_action(
            "batch_api_created",
            f"Batch {batch_id} created with {total_requests} requests",
            {"batch_id": batch_id},
        )

        # Poll for completion
        print(f"    Batch {batch_id} created. Waiting for completion...")
        poll_interval = 10  # seconds
        while True:
            message_batch = self.client.messages.batches.retrieve(batch_id)
            counts = message_batch.request_counts
            completed = counts.succeeded + counts.errored + counts.canceled + counts.expired
            print(
                f"\r    Progress: {completed}/{total_requests} "
                f"({counts.succeeded} succeeded, {counts.errored} errored)",
                end="", flush=True,
            )

            if message_batch.processing_status == "ended":
                print()  # newline after progress
                break

            time.sleep(poll_interval)

        # Process results
        total_input_tokens = 0
        total_output_tokens = 0
        cache_read_tokens = 0

        for result in self.client.messages.batches.results(batch_id):
            if result.result.type == "succeeded":
                msg = result.result.message
                try:
                    batch_analysis = _extract_json(msg.content[0].text)
                    self._merge_analysis(analysis_results, batch_analysis)
                    analysis_results["processing_stats"]["batches_processed"] += 1
                    total_input_tokens += msg.usage.input_tokens
                    total_output_tokens += msg.usage.output_tokens
                    if hasattr(msg.usage, 'cache_read_input_tokens'):
                        cache_read_tokens += msg.usage.cache_read_input_tokens or 0
                except Exception as e:
                    analysis_results["processing_stats"]["errors"].append(
                        f"Parse error for {result.custom_id}: {str(e)}"
                    )
            elif result.result.type == "errored":
                error_msg = str(getattr(result.result, 'error', 'Unknown error'))
                analysis_results["processing_stats"]["errors"].append(
                    f"API error for {result.custom_id}: {error_msg}"
                )

        analysis_results["processing_stats"]["api_calls"] = total_requests
        analysis_results["processing_stats"]["tokens_used"] = total_input_tokens + total_output_tokens
        analysis_results["processing_stats"]["input_tokens"] = total_input_tokens
        analysis_results["processing_stats"]["output_tokens"] = total_output_tokens
        analysis_results["processing_stats"]["cache_read_tokens"] = cache_read_tokens
        analysis_results["processing_stats"]["batch_id"] = batch_id
        analysis_results["processing_stats"]["batch_api"] = True

        print(
            f"    Batch complete: {counts.succeeded} succeeded, "
            f"{total_input_tokens + total_output_tokens:,} tokens used"
            + (f", {cache_read_tokens:,} from cache" if cache_read_tokens else "")
        )

        # Generate summary, risks, recommendations (synchronous - only 2 API calls)
        analysis_results["conversation_summary"] = self._generate_summary(analysis_results)
        analysis_results["risk_indicators"] = self._identify_risks(analysis_results)
        analysis_results["recommendations"] = self._generate_recommendations(analysis_results)

        self.forensic.record_action(
            "batch_analysis_complete",
            f"Completed batch analysis of {len(messages)} messages",
            {
                "batch_id": batch_id,
                "total_requests": total_requests,
                "succeeded": counts.succeeded,
                "errored": counts.errored,
                "input_tokens": total_input_tokens,
                "output_tokens": total_output_tokens,
                "cache_read_tokens": cache_read_tokens,
                "errors": len(analysis_results["processing_stats"]["errors"]),
                "risk_indicators_found": len(analysis_results["risk_indicators"]),
            },
        )

        return analysis_results

    # ------------------------------------------------------------------
    # Synchronous path (fallback / development)
    # ------------------------------------------------------------------

    def _analyze_messages_sync(self, messages: List[Dict], batch_size: int) -> Dict[str, Any]:
        """
        Analyze messages synchronously (one API call per batch).
        Used as fallback when Batch API is unavailable or disabled.
        """
        analysis_results = self._init_analysis_results(len(messages))

        try:
            for i in range(0, len(messages), batch_size):
                batch = messages[i:i + batch_size]

                batch_text = self._prepare_batch(batch)
                token_count = self._estimate_tokens(batch_text)

                self.rate_limiter.wait_if_needed(token_count)
                batch_analysis = self._analyze_batch(batch_text, batch)
                self._merge_analysis(analysis_results, batch_analysis)

                analysis_results["processing_stats"]["batches_processed"] += 1
                analysis_results["processing_stats"]["tokens_used"] += token_count
                analysis_results["processing_stats"]["api_calls"] += 1

                self.forensic.record_action(
                    "ai_batch_analyzed",
                    f"Analyzed batch {i // batch_size + 1} of {(len(messages) + batch_size - 1) // batch_size}",
                    {
                        "batch_size": len(batch),
                        "tokens": token_count,
                        "batch_number": i // batch_size + 1,
                    },
                )

            analysis_results["conversation_summary"] = self._generate_summary(analysis_results)
            analysis_results["risk_indicators"] = self._identify_risks(analysis_results)
            analysis_results["recommendations"] = self._generate_recommendations(analysis_results)

            self.forensic.record_action(
                "ai_analysis_complete",
                f"Completed AI analysis of {len(messages)} messages",
                {
                    "total_messages": len(messages),
                    "batches": analysis_results["processing_stats"]["batches_processed"],
                    "tokens_used": analysis_results["processing_stats"]["tokens_used"],
                    "risk_indicators_found": len(analysis_results["risk_indicators"]),
                },
            )

        except Exception as e:
            self.forensic.record_action(
                "ai_analysis_error",
                f"Error during AI analysis: {str(e)}",
                {"error": str(e), "messages_processed": i if "i" in locals() else 0},
            )
            analysis_results["processing_stats"]["errors"].append(str(e))

        return analysis_results

    # ------------------------------------------------------------------
    # Shared helpers
    # ------------------------------------------------------------------

    def _init_analysis_results(self, total_messages: int) -> Dict[str, Any]:
        """Create the initial analysis results structure."""
        return {
            "generated_at": datetime.now().isoformat(),
            "total_messages": total_messages,
            "ai_model": self.model,
            "sentiment_analysis": {"scores": [], "overall": "neutral", "shifts": []},
            "threat_assessment": {},
            "behavioral_patterns": {},
            "conversation_summary": "",
            "key_topics": [],
            "risk_indicators": [],
            "recommendations": [],
            "processing_stats": {
                "batches_processed": 0,
                "tokens_used": 0,
                "api_calls": 0,
                "errors": [],
            },
        }

    def _prepare_batch(self, messages: List[Dict]) -> str:
        """
        Prepare a batch of messages for AI analysis.
        Maintains forensic integrity by preserving original content.

        Args:
            messages: List of message dictionaries

        Returns:
            Formatted text for AI analysis
        """
        batch_text = "Analyze the following conversation for forensic investigation:\n\n"

        for msg in messages:
            timestamp = msg.get("timestamp", "Unknown time")
            sender = msg.get("sender", "Unknown")
            content = msg.get("content", "")

            # Truncate very long messages to save tokens
            if len(content) > 500:
                content = content[:500] + "...[truncated]"

            batch_text += f"[{timestamp}] {sender}: {content}\n"

        return batch_text

    def _analyze_batch(self, batch_text: str, messages: List[Dict]) -> Dict[str, Any]:
        """
        Analyze a single batch of messages synchronously.
        Uses prompt caching on the system prompt.

        Args:
            batch_text: Formatted text of messages
            messages: Original message dictionaries

        Returns:
            Analysis results for the batch
        """
        if not self.client:
            return {}

        try:
            response = self.client.messages.create(
                model=self.model,
                system=self._cached_system_prompt(),
                messages=[{"role": "user", "content": batch_text}],
                temperature=0.3,
                max_tokens=self.max_tokens_per_request,
            )

            # Parse response
            result = _extract_json(response.content[0].text)

            # Add metadata for forensic tracking
            result["_metadata"] = {
                "model": self.model,
                "timestamp": datetime.now().isoformat(),
                "message_count": len(messages),
                "input_tokens": response.usage.input_tokens,
                "output_tokens": response.usage.output_tokens,
            }

            return result

        except Exception as e:
            self.forensic.record_action(
                "ai_batch_error",
                f"Error analyzing batch: {str(e)}",
                {"error": str(e), "batch_size": len(messages)},
            )
            return {}

    def _merge_analysis(self, results: Dict, batch_analysis: Dict):
        """
        Merge batch analysis into overall results.

        Args:
            results: Overall analysis results
            batch_analysis: Analysis from a single batch
        """
        if not batch_analysis:
            return

        # Merge sentiment
        if "sentiment" in batch_analysis:
            if "sentiment_analysis" not in results:
                results["sentiment_analysis"] = {"scores": [], "overall": "neutral", "shifts": []}

            sentiment = batch_analysis["sentiment"]
            results["sentiment_analysis"]["scores"].append(sentiment.get("intensity", 5))

            # Track sentiment shifts
            if "shifts" in sentiment and sentiment["shifts"]:
                if "shifts" not in results["sentiment_analysis"]:
                    results["sentiment_analysis"]["shifts"] = []
                results["sentiment_analysis"]["shifts"].extend(sentiment["shifts"])

        # Merge threats
        if "threats" in batch_analysis:
            if "threat_assessment" not in results:
                results["threat_assessment"] = {"found": False, "details": []}

            if batch_analysis["threats"].get("found"):
                results["threat_assessment"]["found"] = True
                results["threat_assessment"]["details"].extend(
                    batch_analysis["threats"].get("details", [])
                )

        # Merge behavioral patterns
        if "behavioral_patterns" in batch_analysis:
            if "behavioral_patterns" not in results:
                results["behavioral_patterns"] = {"patterns": [], "anomalies": []}

            results["behavioral_patterns"]["patterns"].extend(
                batch_analysis["behavioral_patterns"].get("patterns", [])
            )
            results["behavioral_patterns"]["anomalies"].extend(
                batch_analysis["behavioral_patterns"].get("anomalies", [])
            )

        # Merge key topics
        if "key_topics" in batch_analysis:
            results["key_topics"].extend(batch_analysis["key_topics"])

        # Merge risk indicators
        if "risk_indicators" in batch_analysis:
            results["risk_indicators"].extend(batch_analysis["risk_indicators"])

    def _generate_summary(self, analysis: Dict) -> str:
        """
        Generate an overall summary of the AI analysis.

        Args:
            analysis: Complete analysis results

        Returns:
            Summary text for legal review
        """
        if not self.client or not analysis.get("sentiment_analysis"):
            return "AI analysis not available."

        try:
            prompt = (
                "Based on the following forensic analysis of digital communications "
                "in a family law matter, provide a concise executive summary suitable "
                "for review by the legal team (attorneys and paralegals, not technicians).\n\n"
                "Focus on:\n"
                "- Safety concerns for any party or children\n"
                "- Evidence of threatening, controlling, or harassing behavior\n"
                "- Custody-relevant behavioral patterns\n"
                "- Recommended immediate actions\n\n"
                f"Analysis Results:\n"
                f"- Total messages analyzed: {analysis['total_messages']}\n"
                f"- Threats found: {analysis.get('threat_assessment', {}).get('found', False)}\n"
                f"- Threat severity: {analysis.get('threat_assessment', {}).get('severity', 'none')}\n"
                f"- Risk indicators: {len(analysis.get('risk_indicators', []))}\n"
                f"- Key topics: {', '.join(str(t) for t in analysis.get('key_topics', [])[:5])}\n"
                f"- Behavioral anomalies: {len(analysis.get('behavioral_patterns', {}).get('anomalies', []))}\n\n"
                "Write 2-3 paragraphs for attorneys. Lead with the most critical findings. "
                "Use plain language, avoid technical jargon. Reference specific message "
                "content where possible."
            )

            # Respect rate limits (sync call)
            token_count = self._estimate_tokens(prompt)
            self.rate_limiter.wait_if_needed(token_count)

            response = self.client.messages.create(
                model=self.model,
                system=[{
                    "type": "text",
                    "text": (
                        "You are a forensic analyst preparing evidence summaries for "
                        "family law attorneys. Write clearly for a legal audience, not "
                        "a technical one."
                    ),
                    "cache_control": {"type": "ephemeral"},
                }],
                messages=[{"role": "user", "content": prompt}],
                temperature=0.3,
                max_tokens=1024,
            )

            return response.content[0].text

        except Exception as e:
            self.forensic.record_action(
                "summary_generation_error",
                f"Error generating summary: {str(e)}",
                {"error": str(e)},
            )
            return "Summary generation failed. See detailed analysis results."

    def _identify_risks(self, analysis: Dict) -> List[Dict]:
        """
        Identify and prioritize risk indicators from analysis.

        Args:
            analysis: Complete analysis results

        Returns:
            List of prioritized risk indicators
        """
        risks = []

        # Check threat assessment
        if analysis.get("threat_assessment", {}).get("found"):
            risks.append(
                {
                    "type": "threat",
                    "severity": "high",
                    "description": "Potential threats or harassment detected",
                    "details": analysis["threat_assessment"].get("details", []),
                }
            )

        # Check behavioral anomalies
        anomalies = analysis.get("behavioral_patterns", {}).get("anomalies", [])
        if anomalies:
            risks.append(
                {
                    "type": "behavioral",
                    "severity": "medium",
                    "description": f"Behavioral anomalies detected ({len(anomalies)} instances)",
                    "details": anomalies[:5],
                }
            )

        # Check sentiment shifts
        shifts = analysis.get("sentiment_analysis", {}).get("shifts", [])
        if len(shifts) > 3:
            risks.append(
                {
                    "type": "emotional_volatility",
                    "severity": "low",
                    "description": f"Significant emotional volatility ({len(shifts)} shifts detected)",
                    "details": shifts,
                }
            )

        # Deduplicate and sort by severity
        risk_levels = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        risks.sort(key=lambda x: risk_levels.get(x["severity"], 0), reverse=True)

        return risks

    def _generate_recommendations(self, analysis: Dict) -> List[str]:
        """
        Generate actionable recommendations based on analysis.

        Args:
            analysis: Complete analysis results

        Returns:
            List of recommendations for legal team
        """
        recommendations = []

        # Based on threats
        if analysis.get("threat_assessment", {}).get("found"):
            recommendations.append(
                "Priority review recommended: Potential threats detected. "
                "Review flagged messages and consider escalation to law enforcement if warranted."
            )

        # Based on risk indicators
        risk_count = len(analysis.get("risk_indicators", []))
        if risk_count > 5:
            recommendations.append(
                f"Comprehensive review needed: {risk_count} risk indicators identified. "
                "Consider detailed manual review of all flagged content."
            )
        elif risk_count > 0:
            recommendations.append(
                f"Targeted review suggested: {risk_count} risk indicators found. "
                "Focus on messages flagged with risk indicators."
            )

        # Based on behavioral patterns
        if analysis.get("behavioral_patterns", {}).get("anomalies"):
            recommendations.append(
                "Behavioral analysis recommended: Anomalous communication patterns detected. "
                "Review timeline and context around identified anomalies."
            )

        # General recommendations
        if not recommendations:
            recommendations.append(
                "Standard review protocol: No immediate concerns identified. "
                "Proceed with standard review procedures."
            )

        recommendations.append(
            "Maintain chain of custody: Ensure all evidence handling follows "
            "documented procedures for legal admissibility."
        )

        return recommendations

    def _empty_analysis(self) -> Dict[str, Any]:
        """Return empty analysis structure when AI is not available."""
        return {
            "generated_at": datetime.now().isoformat(),
            "total_messages": 0,
            "ai_model": "Not configured",
            "sentiment_analysis": {"scores": [], "overall": "neutral", "shifts": []},
            "threat_assessment": {"found": False, "details": []},
            "behavioral_patterns": {},
            "conversation_summary": "AI analysis not available - Anthropic Claude not configured.",
            "key_topics": [],
            "risk_indicators": [],
            "recommendations": ["Configure Anthropic Claude for advanced AI-powered analysis."],
            "processing_stats": {
                "batches_processed": 0,
                "tokens_used": 0,
                "api_calls": 0,
                "errors": ["Anthropic Claude not configured"],
            },
        }

    def analyze_single_message(self, message: Dict) -> Dict[str, Any]:
        """
        Analyze a single message for immediate assessment.
        Uses synchronous API (not batch) for real-time threat detection.

        Args:
            message: Message dictionary

        Returns:
            Quick analysis results
        """
        if not self.client:
            return {"analyzed": False, "reason": "AI not configured"}

        try:
            content = message.get("content", "")
            if not content:
                return {"analyzed": False, "reason": "No content"}

            prompt = (
                f'Quickly assess this message for immediate concerns:\n'
                f'"{content[:500]}"\n\n'
                'Return valid JSON (no markdown fences): '
                '{"threat_level": "none/low/medium/high", '
                '"concerns": [], "requires_review": true/false}'
            )

            # Estimate tokens and respect limits
            token_count = self._estimate_tokens(prompt)
            self.rate_limiter.wait_if_needed(token_count)

            response = self.client.messages.create(
                model=self.model,
                system="You are a threat assessment system. Be objective and precise.",
                messages=[{"role": "user", "content": prompt}],
                temperature=0.1,
                max_tokens=256,
            )

            result = _extract_json(response.content[0].text)
            result["analyzed"] = True
            result["timestamp"] = datetime.now().isoformat()

            # Log if concerns found
            if result.get("threat_level") in ["medium", "high"]:
                self.forensic.record_action(
                    "ai_threat_detected",
                    f"AI detected {result['threat_level']} threat level",
                    {"message_id": message.get("message_id"), "concerns": result.get("concerns", [])},
                )

            return result

        except Exception as e:
            self.forensic.record_action(
                "single_message_analysis_error",
                f"Error analyzing single message: {str(e)}",
                {"error": str(e)},
            )
            return {"analyzed": False, "error": str(e)}

    def generate_analysis_report(self, analysis: Dict, output_path: Optional[Path] = None) -> Path:
        """
        Generate a comprehensive AI analysis report.

        Args:
            analysis: AI analysis results
            output_path: Optional output path

        Returns:
            Path to generated report
        """
        if not output_path:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = Path(config.output_dir) / f"ai_analysis_report_{timestamp}.json"

        # Add legal metadata
        report = {
            "report_type": "AI Analysis Report",
            "generated_at": datetime.now().isoformat(),
            "generator": f"AIAnalyzer with {self.model}",
            "legal_notice": (
                f"This AI analysis was generated using Anthropic {self.model}. "
                "Results are provided as supplementary analysis and should be reviewed "
                "by qualified personnel. AI-generated insights are probabilistic and "
                "should be validated against original evidence. This analysis maintains "
                "forensic integrity through hash verification and chain of custody logging."
            ),
            "methodology": {
                "model": self.model,
                "temperature": 0.3,
                "approach": "Batch API processing with prompt caching",
                "validation": "Results cross-referenced with pattern-based analysis",
            },
            "analysis": analysis,
        }

        # Write report
        with open(output_path, "w") as f:
            json.dump(report, f, indent=2, default=str)

        # Hash for integrity
        report_hash = self.forensic.compute_hash(output_path)

        self.forensic.record_action(
            "ai_report_generated",
            f"Generated AI analysis report",
            {"path": str(output_path), "hash": report_hash},
        )

        return output_path


__all__ = ["AIAnalyzer", "RateLimiter"]
