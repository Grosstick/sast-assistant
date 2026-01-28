"""Google Gemini API client for vulnerability analysis.

Uses google-genai SDK: https://ai.google.dev/gemini-api/docs
Retry logic with tenacity: https://tenacity.readthedocs.io/
(tenacity is way easier than writing retry loops manually)
"""

import json
import logging
import re
from typing import Optional

from google import genai
from google.genai import types
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type

from ..config import GeminiConfig
from ..models.finding import EnrichedFinding, AIAnalysis, TriageVerdict, CodeContext, VulnerabilityType
from ..models.semgrep import SemgrepFinding
from .prompts import SYSTEM_PROMPT, get_analysis_prompt

logger = logging.getLogger(__name__)


class GeminiClientError(Exception):
    """Exception raised when Gemini API calls fail."""
    pass


class GeminiClient:
    """Client for Google Gemini API for vulnerability analysis."""
    
    def __init__(self, config: Optional[GeminiConfig] = None):
        self.config = config or GeminiConfig()
        self._client: Optional[genai.Client] = None
    
    @property
    def client(self) -> genai.Client:
        if self._client is None:
            self._client = genai.Client(api_key=self.config.get_api_key())
        return self._client
    
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=10),
        retry=retry_if_exception_type((ConnectionError, TimeoutError)),
        reraise=True,
    )
    def analyze_finding(
        self,
        finding: SemgrepFinding,
        context: CodeContext,
        vulnerability_type: VulnerabilityType,
    ) -> AIAnalysis:
        """Analyze a single vulnerability finding using Gemini."""
        try:
            code_context = context.get_formatted_code(include_line_numbers=True)
            user_prompt = get_analysis_prompt(
                code_context=code_context,
                rule_id=finding.rule_id,
                vulnerability_type=vulnerability_type,
                language=context.get_language(),
                message=finding.message,
            )
            
            logger.debug(f"Analyzing finding: {finding.rule_id} at {finding.path}:{finding.line_number}")
            
            response = self.client.models.generate_content(
                model=self.config.model,
                contents=user_prompt,
                config=types.GenerateContentConfig(
                    system_instruction=SYSTEM_PROMPT,
                    temperature=self.config.temperature,
                    max_output_tokens=self.config.max_tokens,
                ),
            )
            
            return self._parse_analysis_response(response.text)
            
        except json.JSONDecodeError as e:
            logger.warning(f"Failed to parse Gemini response as JSON: {e}")
            return AIAnalysis(
                verdict=TriageVerdict.NEEDS_REVIEW,
                confidence=0.0,
                explanation="Failed to parse AI response",
                analysis_error=f"JSON parse error: {e}",
            )
        except Exception as e:
            logger.error(f"Gemini API error: {e}")
            return AIAnalysis(
                verdict=TriageVerdict.NEEDS_REVIEW,
                confidence=0.0,
                explanation="AI analysis failed",
                analysis_error=str(e),
            )
    
    def _parse_analysis_response(self, response_text: str) -> AIAnalysis:
        """Parse the Gemini response into an AIAnalysis object."""
        text = response_text.strip()
        
        if text.startswith("```json"):
            text = text[7:]
        if text.startswith("```"):
            text = text[3:]
        if text.endswith("```"):
            text = text[:-3]
        text = text.strip()
        
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            json_match = re.search(r'\{[^{}]*\}', text, re.DOTALL)
            if json_match:
                data = json.loads(json_match.group())
            else:
                raise
        
        verdict_str = data.get("verdict", "needs_review").lower().replace("-", "_")
        verdict_map = {
            "true_positive": TriageVerdict.TRUE_POSITIVE,
            "false_positive": TriageVerdict.FALSE_POSITIVE,
            "needs_review": TriageVerdict.NEEDS_REVIEW,
        }
        verdict = verdict_map.get(verdict_str, TriageVerdict.NEEDS_REVIEW)
        
        return AIAnalysis(
            verdict=verdict,
            confidence=float(data.get("confidence", 0.5)),
            explanation=data.get("explanation", ""),
            why_vulnerable=data.get("why_vulnerable", ""),
            risk_description=data.get("risk_description", ""),
            suggested_fix=data.get("suggested_fix", ""),
            fix_explanation=data.get("fix_explanation", ""),
            security_principle=data.get("security_principle", ""),
            common_mistakes=data.get("common_mistakes", []),
            attack_scenario=data.get("attack_scenario", ""),
        )
    
    def analyze_findings_batch(
        self,
        findings: list[tuple[SemgrepFinding, CodeContext, VulnerabilityType]],
    ) -> list[AIAnalysis]:
        """Analyze multiple findings in batches."""
        results: list[AIAnalysis] = []
        batch_size = self.config.batch_size
        
        for i in range(0, len(findings), batch_size):
            batch = findings[i : i + batch_size]
            logger.info(f"Processing batch {i // batch_size + 1} ({len(batch)} findings)")
            
            for finding, context, vuln_type in batch:
                try:
                    analysis = self.analyze_finding(finding, context, vuln_type)
                    results.append(analysis)
                except Exception as e:
                    logger.error(f"Failed to analyze finding: {e}")
                    results.append(AIAnalysis(
                        verdict=TriageVerdict.NEEDS_REVIEW,
                        confidence=0.0,
                        explanation="Analysis failed",
                        analysis_error=str(e),
                    ))
        
        return results
    
    def enrich_finding(self, finding: SemgrepFinding, context: CodeContext) -> EnrichedFinding:
        """Create an enriched finding with AI analysis."""
        enriched = EnrichedFinding(original=finding, context=context)
        
        try:
            analysis = self.analyze_finding(
                finding=finding,
                context=context,
                vulnerability_type=enriched.vulnerability_type,
            )
            enriched.ai_analysis = analysis
        except Exception as e:
            logger.error(f"Failed to enrich finding: {e}")
            enriched.ai_analysis = AIAnalysis(
                verdict=TriageVerdict.NEEDS_REVIEW,
                analysis_error=str(e),
            )
        
        return enriched
    
    def test_connection(self) -> tuple[bool, str]:
        """Test the Gemini API connection."""
        try:
            response = self.client.models.generate_content(
                model=self.config.model,
                contents="Say 'API connection successful' in exactly those words.",
                config=types.GenerateContentConfig(max_output_tokens=50),
            )
            return True, f"Connection successful: {response.text[:50]}"
        except Exception as e:
            return False, f"Connection failed: {e}"
