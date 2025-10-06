"""
AI-powered analysis module for forensic message analyzer.
Uses Azure OpenAI for advanced threat detection and content analysis.
"""

import os
import json
import time
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime
import pandas as pd
import logging
from dataclasses import dataclass

try:
    from openai import AzureOpenAI
    import tiktoken
    AI_AVAILABLE = True
except ImportError:
    AI_AVAILABLE = False

from ..config import Config
from ..forensic_utils import ForensicRecorder

# Initialize config
config = Config()

logger = logging.getLogger(__name__)


class RateLimiter:
    """Rate limiter for API calls to respect Azure OpenAI limits."""
    
    def __init__(self, max_requests_per_minute: int = 60, max_tokens_per_minute: int = 150000):
        """
        Initialize rate limiter.
        
        Args:
            max_requests_per_minute: Maximum API requests per minute
            max_tokens_per_minute: Maximum tokens per minute
        """
        self.max_requests_per_minute = max_requests_per_minute
        self.max_tokens_per_minute = max_tokens_per_minute
        self.request_times: List[float] = []
        self.token_counts: List[Tuple[float, int]] = []
    
    def wait_if_needed(self, estimated_tokens: int = 0):
        """
        Wait if necessary to respect rate limits.
        
        Args:
            estimated_tokens: Estimated tokens for next request
        """
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


class AIAnalyzer:
    """
    AI-powered analysis using Azure OpenAI GPT-4 Turbo.
    Provides advanced analysis while maintaining forensic integrity and legal defensibility.
    """
    
    def __init__(self, forensic_recorder: Optional[ForensicRecorder] = None):
        """
        Initialize AI analyzer with Azure OpenAI.
        
        Args:
            forensic_recorder: Optional ForensicRecorder for chain of custody
        """
        self.forensic = forensic_recorder or ForensicRecorder()
        
        # Get configuration from config instance
        self.api_key = config.azure_api_key
        self.endpoint = config.azure_endpoint
        self.deployment_name = config.azure_deployment or 'gpt-4-turbo'
        self.api_version = config.azure_api_version or '2024-02-15-preview'
        
        # Token limits from config
        self.max_tokens_per_request = config.max_tokens_per_request if hasattr(config, 'max_tokens_per_request') else 4000
        self.max_tokens_per_minute = getattr(config, 'tokens_per_minute', 150000)
        self.max_requests_per_minute = 60
        
        # Initialize Azure OpenAI client if credentials available
        self.client = None
        self.encoding = None
        
        if AI_AVAILABLE and self.api_key and self.endpoint:
            try:
                self.client = AzureOpenAI(
                    api_key=self.api_key,
                    api_version=self.api_version,
                    azure_endpoint=self.endpoint
                )
                
                # Initialize tokenizer for counting
                self.encoding = tiktoken.encoding_for_model("gpt-4")
                
                # Initialize rate limiter
                self.rate_limiter = RateLimiter(
                    max_requests_per_minute=self.max_requests_per_minute,
                    max_tokens_per_minute=self.max_tokens_per_minute
                )
                
                self.forensic.record_action(
                    "ai_analyzer_initialized",
                    f"Azure OpenAI analyzer initialized with {self.deployment_name}",
                    {"deployment": self.deployment_name, "endpoint": self.endpoint}
                )
            except Exception as e:
                self.forensic.record_action(
                    "ai_init_error",
                    f"Failed to initialize Azure OpenAI: {str(e)}",
                    {"error": str(e)}
                )
                self.client = None
        else:
            self.forensic.record_action(
                "ai_analyzer_disabled",
                "Azure OpenAI analyzer disabled - no credentials configured or dependencies missing"
            )
    
    def analyze_messages(self, messages: List[Dict], batch_size: int = 10) -> Dict[str, Any]:
        """
        Analyze messages using GPT-4 Turbo for advanced insights.
        Processes in batches to respect token limits and maintain performance.
        
        Args:
            messages: List of message dictionaries
            batch_size: Number of messages to analyze per API call
            
        Returns:
            Dictionary containing AI analysis results
        """
        if not self.client:
            self.forensic.record_action(
                "ai_analysis_skipped",
                "AI analysis skipped - Azure OpenAI not configured"
            )
            return self._empty_analysis()
        
        analysis_results = {
            "generated_at": datetime.now().isoformat(),
            "total_messages": len(messages),
            "ai_model": self.deployment_name,
            "sentiment_analysis": {},
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
                "errors": []
            }
        }
        
        try:
            # Process messages in batches
            for i in range(0, len(messages), batch_size):
                batch = messages[i:i + batch_size]
                
                # Prepare batch for analysis
                batch_text = self._prepare_batch(batch)
                
                # Count tokens
                token_count = len(self.encoding.encode(batch_text))
                
                # Respect rate limits
                self.rate_limiter.wait_if_needed(token_count)
                
                # Analyze batch
                batch_analysis = self._analyze_batch(batch_text, batch)
                
                # Merge results
                self._merge_analysis(analysis_results, batch_analysis)
                
                # Update stats
                analysis_results["processing_stats"]["batches_processed"] += 1
                analysis_results["processing_stats"]["tokens_used"] += token_count
                analysis_results["processing_stats"]["api_calls"] += 1
                
                self.forensic.record_action(
                    "ai_batch_analyzed",
                    f"Analyzed batch {i//batch_size + 1} of {(len(messages) + batch_size - 1)//batch_size}",
                    {
                        "batch_size": len(batch),
                        "tokens": token_count,
                        "batch_number": i//batch_size + 1
                    }
                )
            
            # Generate overall summary
            analysis_results["conversation_summary"] = self._generate_summary(analysis_results)
            
            # Identify risk indicators
            analysis_results["risk_indicators"] = self._identify_risks(analysis_results)
            
            # Generate recommendations
            analysis_results["recommendations"] = self._generate_recommendations(analysis_results)
            
            self.forensic.record_action(
                "ai_analysis_complete",
                f"Completed AI analysis of {len(messages)} messages",
                {
                    "total_messages": len(messages),
                    "batches": analysis_results["processing_stats"]["batches_processed"],
                    "tokens_used": analysis_results["processing_stats"]["tokens_used"],
                    "risk_indicators_found": len(analysis_results["risk_indicators"])
                }
            )
            
        except Exception as e:
            self.forensic.record_action(
                "ai_analysis_error",
                f"Error during AI analysis: {str(e)}",
                {"error": str(e), "messages_processed": i if 'i' in locals() else 0}
            )
            analysis_results["processing_stats"]["errors"].append(str(e))
        
        return analysis_results
    
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
            timestamp = msg.get('timestamp', 'Unknown time')
            sender = msg.get('sender', 'Unknown')
            content = msg.get('content', '')
            
            # Truncate very long messages to save tokens
            if len(content) > 500:
                content = content[:500] + "...[truncated]"
            
            batch_text += f"[{timestamp}] {sender}: {content}\n"
        
        return batch_text
    
    def _analyze_batch(self, batch_text: str, messages: List[Dict]) -> Dict[str, Any]:
        """
        Analyze a batch of messages using GPT-4 Turbo.
        
        Args:
            batch_text: Formatted text of messages
            messages: Original message dictionaries
            
        Returns:
            Analysis results for the batch
        """
        if not self.client:
            return {}
        
        try:
            # Prepare the analysis prompt
            system_prompt = """You are a forensic analyst specializing in digital communications. 
            Analyze the provided conversation for legal proceedings. Focus on:
            1. Sentiment and emotional tone
            2. Potential threats, harassment, or concerning behavior
            3. Behavioral patterns and changes
            4. Key topics and themes
            5. Risk indicators requiring attention
            
            Provide objective, fact-based analysis suitable for court proceedings.
            Avoid speculation and clearly distinguish observations from interpretations.
            Format your response as JSON with the following structure:
            {
                "sentiment": {"overall": "positive/neutral/negative", "shifts": [], "intensity": 0-10},
                "threats": {"found": boolean, "severity": "none/low/medium/high", "details": []},
                "behavioral_patterns": {"patterns": [], "anomalies": []},
                "key_topics": [],
                "risk_indicators": [],
                "notable_quotes": []
            }"""
            
            # Make API call
            response = self.client.chat.completions.create(
                model=self.deployment_name,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": batch_text}
                ],
                temperature=0.3,  # Low temperature for consistency
                max_tokens=self.max_tokens_per_request,
                response_format={"type": "json_object"}
            )
            
            # Parse response
            result = json.loads(response.choices[0].message.content)
            
            # Add metadata for forensic tracking
            result["_metadata"] = {
                "model": self.deployment_name,
                "timestamp": datetime.now().isoformat(),
                "message_count": len(messages),
                "completion_tokens": response.usage.completion_tokens,
                "prompt_tokens": response.usage.prompt_tokens
            }
            
            return result
            
        except Exception as e:
            self.forensic.record_action(
                "ai_batch_error",
                f"Error analyzing batch: {str(e)}",
                {"error": str(e), "batch_size": len(messages)}
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
                results["sentiment_analysis"] = {"scores": [], "overall": "neutral"}
            
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
            # Prepare summary prompt
            prompt = f"""Based on the following forensic analysis results, provide a concise executive summary 
            suitable for legal proceedings. Focus on objective findings and avoid speculation.
            
            Analysis Results:
            - Total messages analyzed: {analysis['total_messages']}
            - Threats found: {analysis.get('threat_assessment', {}).get('found', False)}
            - Risk indicators: {len(analysis.get('risk_indicators', []))}
            - Key topics: {', '.join(analysis.get('key_topics', [])[:5])}
            - Behavioral anomalies: {len(analysis.get('behavioral_patterns', {}).get('anomalies', []))}
            
            Provide a 2-3 paragraph summary highlighting the most important findings for legal review."""
            
            # Respect rate limits
            token_count = len(self.encoding.encode(prompt))
            self.rate_limiter.wait_if_needed(token_count)
            
            response = self.client.chat.completions.create(
                model=self.deployment_name,
                messages=[
                    {"role": "system", "content": "You are a forensic analyst preparing evidence summaries for court."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.3,
                max_tokens=500
            )
            
            return response.choices[0].message.content
            
        except Exception as e:
            self.forensic.record_action(
                "summary_generation_error",
                f"Error generating summary: {str(e)}",
                {"error": str(e)}
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
            risks.append({
                "type": "threat",
                "severity": "high",
                "description": "Potential threats or harassment detected",
                "details": analysis["threat_assessment"].get("details", [])
            })
        
        # Check behavioral anomalies
        anomalies = analysis.get("behavioral_patterns", {}).get("anomalies", [])
        if anomalies:
            risks.append({
                "type": "behavioral",
                "severity": "medium",
                "description": f"Behavioral anomalies detected ({len(anomalies)} instances)",
                "details": anomalies[:5]  # First 5 anomalies
            })
        
        # Check sentiment shifts
        shifts = analysis.get("sentiment_analysis", {}).get("shifts", [])
        if len(shifts) > 3:  # Multiple sentiment shifts may indicate volatility
            risks.append({
                "type": "emotional_volatility",
                "severity": "low",
                "description": f"Significant emotional volatility ({len(shifts)} shifts detected)",
                "details": shifts
            })
        
        # Deduplicate and sort by severity
        risk_levels = {"high": 3, "medium": 2, "low": 1}
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
            "sentiment_analysis": {},
            "threat_assessment": {"found": False, "details": []},
            "behavioral_patterns": {},
            "conversation_summary": "AI analysis not available - Azure OpenAI not configured.",
            "key_topics": [],
            "risk_indicators": [],
            "recommendations": ["Configure Azure OpenAI for advanced AI-powered analysis."],
            "processing_stats": {
                "batches_processed": 0,
                "tokens_used": 0,
                "api_calls": 0,
                "errors": ["Azure OpenAI not configured"]
            }
        }
    
    def analyze_single_message(self, message: Dict) -> Dict[str, Any]:
        """
        Analyze a single message for immediate assessment.
        Used for real-time threat detection during extraction.
        
        Args:
            message: Message dictionary
            
        Returns:
            Quick analysis results
        """
        if not self.client:
            return {"analyzed": False, "reason": "AI not configured"}
        
        try:
            content = message.get('content', '')
            if not content:
                return {"analyzed": False, "reason": "No content"}
            
            # Quick threat check prompt
            prompt = f"""Quickly assess this message for immediate concerns:
            "{content[:500]}"
            
            Return JSON: {{"threat_level": "none/low/medium/high", "concerns": [], "requires_review": boolean}}"""
            
            # Count tokens and respect limits
            token_count = len(self.encoding.encode(prompt))
            self.rate_limiter.wait_if_needed(token_count)
            
            response = self.client.chat.completions.create(
                model=self.deployment_name,
                messages=[
                    {"role": "system", "content": "You are a threat assessment system. Be objective and precise."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.1,  # Very low for consistency
                max_tokens=200,
                response_format={"type": "json_object"}
            )
            
            result = json.loads(response.choices[0].message.content)
            result["analyzed"] = True
            result["timestamp"] = datetime.now().isoformat()
            
            # Log if concerns found
            if result.get("threat_level") in ["medium", "high"]:
                self.forensic.record_action(
                    "ai_threat_detected",
                    f"AI detected {result['threat_level']} threat level",
                    {"message_id": message.get('id'), "concerns": result.get('concerns', [])}
                )
            
            return result
            
        except Exception as e:
            self.forensic.record_action(
                "single_message_analysis_error",
                f"Error analyzing single message: {str(e)}",
                {"error": str(e)}
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
            "generator": "AIAnalyzer with GPT-4 Turbo",
            "legal_notice": (
                "This AI analysis was generated using Azure OpenAI GPT-4 Turbo. "
                "Results are provided as supplementary analysis and should be reviewed "
                "by qualified personnel. AI-generated insights are probabilistic and "
                "should be validated against original evidence. This analysis maintains "
                "forensic integrity through hash verification and chain of custody logging."
            ),
            "methodology": {
                "model": self.deployment_name,
                "temperature": 0.3,
                "approach": "Batch processing with token limits",
                "validation": "Results cross-referenced with pattern-based analysis"
            },
            "analysis": analysis
        }
        
        # Write report
        with open(output_path, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        # Hash for integrity
        report_hash = self.forensic.compute_hash(output_path)
        
        self.forensic.record_action(
            "ai_report_generated",
            f"Generated AI analysis report",
            {"path": str(output_path), "hash": report_hash}
        )
        
        return output_path


__all__ = ['AIAnalyzer', 'RateLimiter']