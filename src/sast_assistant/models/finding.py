"""Pydantic models for enriched findings with context and AI analysis."""

from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field

from .semgrep import SemgrepFinding


class VulnerabilityType(str, Enum):
    """Types of vulnerabilities this tool focuses on."""
    
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    OTHER = "other"


class CodeContext(BaseModel):
    """Code context surrounding a vulnerability."""
    
    file_path: str
    vulnerable_line: int
    start_line: int
    end_line: int
    code_lines: list[str] = Field(default_factory=list)
    
    def get_formatted_code(self, include_line_numbers: bool = True) -> str:
        """Get the code context formatted with optional line numbers."""
        if not self.code_lines:
            return ""
        
        lines = []
        for i, line in enumerate(self.code_lines):
            line_num = self.start_line + i
            if include_line_numbers:
                # Mark the vulnerable line with an arrow
                marker = ">>>" if line_num == self.vulnerable_line else "   "
                lines.append(f"{marker} {line_num:4d} | {line}")
            else:
                lines.append(line)
        
        return "\n".join(lines)
    
    def get_language(self) -> str:
        """Infer the programming language from the file path."""
        path_lower = self.file_path.lower()
        if path_lower.endswith(".py"):
            return "python"
        elif path_lower.endswith(".java"):
            return "java"
        elif path_lower.endswith((".js", ".jsx", ".ts", ".tsx")):
            return "javascript"
        else:
            return "unknown"


class TriageVerdict(str, Enum):
    """AI triage verdict on a finding."""
    
    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    NEEDS_REVIEW = "needs_review"


class AIAnalysis(BaseModel):
    """AI-generated analysis of a vulnerability finding."""
    
    verdict: TriageVerdict = TriageVerdict.NEEDS_REVIEW
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    
    # Educational explanation for junior developers
    explanation: str = ""
    why_vulnerable: str = ""
    risk_description: str = ""
    
    # Fix information
    suggested_fix: str = ""
    fix_explanation: str = ""
    
    # Additional educational content
    security_principle: str = ""
    common_mistakes: list[str] = Field(default_factory=list)
    learn_more_links: list[str] = Field(default_factory=list)
    
    # For distinguishing attack types
    attack_scenario: str = ""
    
    # Error handling
    analysis_error: Optional[str] = None
    
    def is_actionable(self) -> bool:
        """Check if this analysis suggests action is needed."""
        return self.verdict == TriageVerdict.TRUE_POSITIVE


class EnrichedFinding(BaseModel):
    """A vulnerability finding enriched with context and AI analysis."""
    
    # Original finding from Semgrep
    original: SemgrepFinding
    
    # Extracted code context
    context: Optional[CodeContext] = None
    
    # AI analysis
    ai_analysis: Optional[AIAnalysis] = None
    
    # Metadata
    vulnerability_type: VulnerabilityType = VulnerabilityType.OTHER
    language: str = "unknown"
    
    def __init__(self, **data):
        super().__init__(**data)
        # Auto-detect vulnerability type and language
        if self.original.is_sql_injection():
            self.vulnerability_type = VulnerabilityType.SQL_INJECTION
        elif self.original.is_xss():
            self.vulnerability_type = VulnerabilityType.XSS
        self.language = self.original.get_language()
    
    @property
    def is_true_positive(self) -> bool:
        """Check if AI analysis determined this is a true positive."""
        if self.ai_analysis:
            return self.ai_analysis.verdict == TriageVerdict.TRUE_POSITIVE
        return False
    
    @property
    def severity(self) -> str:
        """Get the severity from the original finding."""
        return self.original.severity
    
    @property
    def file_path(self) -> str:
        """Get the file path from the original finding."""
        return self.original.file_path
    
    @property
    def line_number(self) -> int:
        """Get the line number from the original finding."""
        return self.original.line_number
    
    @property
    def rule_id(self) -> str:
        """Get the rule ID from the original finding."""
        return self.original.rule_id
    
    def get_summary(self) -> str:
        """Get a one-line summary of this finding."""
        verdict = ""
        if self.ai_analysis:
            verdict = f" [{self.ai_analysis.verdict.value}]"
        return (
            f"{self.original.severity}: {self.vulnerability_type.value} "
            f"in {self.file_path}:{self.line_number}{verdict}"
        )
