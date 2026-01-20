"""Pydantic models for Semgrep JSON output."""

from typing import Optional
from pydantic import BaseModel, Field


class SemgrepPosition(BaseModel):
    """Position in source code (line/column)."""
    
    line: int
    col: int
    offset: int = 0


class SemgrepLocation(BaseModel):
    """Location span in source code."""
    
    start: SemgrepPosition
    end: SemgrepPosition
    path: str


class SemgrepExtra(BaseModel):
    """Extra metadata from Semgrep findings."""
    
    message: str = ""
    severity: str = "WARNING"
    metadata: dict = Field(default_factory=dict)
    lines: str = ""  # The actual code snippet
    is_ignored: bool = False
    fingerprint: str = ""
    
    # Optional fields that may vary by Semgrep version
    fix: Optional[str] = None
    fix_regex: Optional[dict] = None
    dataflow_trace: Optional[dict] = None


class SemgrepFinding(BaseModel):
    """A single vulnerability finding from Semgrep."""
    
    check_id: str  # The rule ID (e.g., "python.lang.security.audit.sqli")
    path: str  # File path
    start: SemgrepPosition
    end: SemgrepPosition
    extra: SemgrepExtra
    
    @property
    def rule_id(self) -> str:
        """Alias for check_id for readability."""
        return self.check_id
    
    @property
    def file_path(self) -> str:
        """Alias for path for readability."""
        return self.path
    
    @property
    def line_number(self) -> int:
        """Get the starting line number."""
        return self.start.line
    
    @property
    def severity(self) -> str:
        """Get the severity level."""
        return self.extra.severity
    
    @property
    def message(self) -> str:
        """Get the finding message."""
        return self.extra.message
    
    @property
    def code_snippet(self) -> str:
        """Get the vulnerable code snippet."""
        return self.extra.lines
    
    def is_sql_injection(self) -> bool:
        """Check if this finding is related to SQL injection."""
        sql_keywords = ["sql", "sqli", "injection", "query"]
        check_lower = self.check_id.lower()
        message_lower = self.message.lower()
        return any(kw in check_lower or kw in message_lower for kw in sql_keywords)
    
    def is_xss(self) -> bool:
        """Check if this finding is related to XSS."""
        xss_keywords = ["xss", "cross-site", "script", "html-injection", "reflected", "stored"]
        check_lower = self.check_id.lower()
        message_lower = self.message.lower()
        return any(kw in check_lower or kw in message_lower for kw in xss_keywords)
    
    def get_language(self) -> str:
        """Infer the programming language from the file path."""
        path_lower = self.path.lower()
        if path_lower.endswith(".py"):
            return "python"
        elif path_lower.endswith(".java"):
            return "java"
        elif path_lower.endswith((".js", ".jsx", ".ts", ".tsx")):
            return "javascript"
        elif path_lower.endswith((".rb")):
            return "ruby"
        elif path_lower.endswith((".go")):
            return "go"
        else:
            return "unknown"


class SemgrepError(BaseModel):
    """An error encountered during Semgrep scanning."""
    
    code: int = 0
    level: str = "error"
    message: str = ""
    path: Optional[str] = None
    type: str = ""


class SemgrepResult(BaseModel):
    """Complete Semgrep scan result."""
    
    results: list[SemgrepFinding] = Field(default_factory=list)
    errors: list[SemgrepError] = Field(default_factory=list)
    version: str = ""
    
    # Optional fields for different Semgrep versions
    paths: Optional[dict] = None
    
    @property
    def finding_count(self) -> int:
        """Get the total number of findings."""
        return len(self.results)
    
    @property
    def error_count(self) -> int:
        """Get the total number of errors."""
        return len(self.errors)
    
    def get_findings_by_severity(self, severity: str) -> list[SemgrepFinding]:
        """Filter findings by severity level."""
        return [f for f in self.results if f.severity.upper() == severity.upper()]
    
    def get_sql_injection_findings(self) -> list[SemgrepFinding]:
        """Get all SQL injection related findings."""
        return [f for f in self.results if f.is_sql_injection()]
    
    def get_xss_findings(self) -> list[SemgrepFinding]:
        """Get all XSS related findings."""
        return [f for f in self.results if f.is_xss()]
    
    def get_findings_by_file(self, file_path: str) -> list[SemgrepFinding]:
        """Get all findings for a specific file."""
        return [f for f in self.results if f.path == file_path]
    
    def get_unique_files(self) -> set[str]:
        """Get the set of unique files with findings."""
        return {f.path for f in self.results}
    
    def get_severity_summary(self) -> dict[str, int]:
        """Get a summary count by severity."""
        summary: dict[str, int] = {}
        for finding in self.results:
            sev = finding.severity.upper()
            summary[sev] = summary.get(sev, 0) + 1
        return summary
