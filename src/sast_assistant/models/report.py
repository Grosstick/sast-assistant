"""Pydantic models for report generation."""

from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field

from .finding import EnrichedFinding, VulnerabilityType, TriageVerdict


class GlossaryEntry(BaseModel):
    """A glossary entry for security terms."""
    
    term: str
    definition: str
    example: Optional[str] = None


class FindingReport(BaseModel):
    """Report section for a single finding."""
    
    finding: EnrichedFinding
    section_number: int
    
    def get_severity_emoji(self) -> str:
        """Get an emoji representing the severity."""
        severity_map = {
            "ERROR": "🔴",
            "WARNING": "🟡",
            "INFO": "🔵",
        }
        return severity_map.get(self.finding.severity.upper(), "⚪")
    
    def get_verdict_emoji(self) -> str:
        """Get an emoji representing the AI verdict."""
        if not self.finding.ai_analysis:
            return "❓"
        verdict_map = {
            TriageVerdict.TRUE_POSITIVE: "⚠️",
            TriageVerdict.FALSE_POSITIVE: "✅",
            TriageVerdict.NEEDS_REVIEW: "🔍",
        }
        return verdict_map.get(self.finding.ai_analysis.verdict, "❓")


class SeveritySummary(BaseModel):
    """Summary of findings by severity."""
    
    error: int = 0
    warning: int = 0
    info: int = 0
    
    @property
    def total(self) -> int:
        return self.error + self.warning + self.info


class VulnerabilityTypeSummary(BaseModel):
    """Summary of findings by vulnerability type."""
    
    sql_injection: int = 0
    xss: int = 0
    other: int = 0
    
    @property
    def total(self) -> int:
        return self.sql_injection + self.xss + self.other


class VerdictSummary(BaseModel):
    """Summary of AI verdicts."""
    
    true_positive: int = 0
    false_positive: int = 0
    needs_review: int = 0
    not_analyzed: int = 0
    
    @property
    def total(self) -> int:
        return self.true_positive + self.false_positive + self.needs_review + self.not_analyzed


class ReportSummary(BaseModel):
    """Executive summary for the scan report."""
    
    total_findings: int = 0
    files_scanned: int = 0
    files_with_findings: int = 0
    
    by_severity: SeveritySummary = Field(default_factory=SeveritySummary)
    by_type: VulnerabilityTypeSummary = Field(default_factory=VulnerabilityTypeSummary)
    by_verdict: VerdictSummary = Field(default_factory=VerdictSummary)
    
    scan_duration_seconds: float = 0.0
    ai_analysis_enabled: bool = True


class ScanReport(BaseModel):
    """Complete scan report."""
    
    # Metadata
    title: str = "SAST Security Scan Report"
    generated_at: datetime = Field(default_factory=datetime.now)
    target_path: str = ""
    
    # Summary
    summary: ReportSummary = Field(default_factory=ReportSummary)
    
    # Detailed findings
    findings: list[FindingReport] = Field(default_factory=list)
    
    # Educational content
    glossary: list[GlossaryEntry] = Field(default_factory=list)
    
    # Scan metadata
    semgrep_version: str = ""
    sast_assistant_version: str = ""
    
    @classmethod
    def from_enriched_findings(
        cls,
        findings: list[EnrichedFinding],
        target_path: str,
        scan_duration: float = 0.0,
        ai_enabled: bool = True,
    ) -> "ScanReport":
        """Create a report from enriched findings."""
        report = cls(target_path=target_path)
        
        # Build summary
        report.summary.total_findings = len(findings)
        report.summary.files_with_findings = len({f.file_path for f in findings})
        report.summary.scan_duration_seconds = scan_duration
        report.summary.ai_analysis_enabled = ai_enabled
        
        # Count by severity
        for f in findings:
            sev = f.severity.upper()
            if sev == "ERROR":
                report.summary.by_severity.error += 1
            elif sev == "WARNING":
                report.summary.by_severity.warning += 1
            else:
                report.summary.by_severity.info += 1
        
        # Count by type
        for f in findings:
            if f.vulnerability_type == VulnerabilityType.SQL_INJECTION:
                report.summary.by_type.sql_injection += 1
            elif f.vulnerability_type == VulnerabilityType.XSS:
                report.summary.by_type.xss += 1
            else:
                report.summary.by_type.other += 1
        
        # Count by verdict
        for f in findings:
            if f.ai_analysis is None:
                report.summary.by_verdict.not_analyzed += 1
            elif f.ai_analysis.verdict == TriageVerdict.TRUE_POSITIVE:
                report.summary.by_verdict.true_positive += 1
            elif f.ai_analysis.verdict == TriageVerdict.FALSE_POSITIVE:
                report.summary.by_verdict.false_positive += 1
            else:
                report.summary.by_verdict.needs_review += 1
        
        # Create finding reports
        for i, f in enumerate(findings, start=1):
            report.findings.append(FindingReport(finding=f, section_number=i))
        
        # Add default glossary
        report.glossary = cls._get_default_glossary()
        
        return report
    
    @staticmethod
    def _get_default_glossary() -> list[GlossaryEntry]:
        """Get the default security glossary for junior developers."""
        return [
            GlossaryEntry(
                term="SQL Injection (SQLi)",
                definition=(
                    "A vulnerability where attackers can insert malicious SQL code into "
                    "queries through user input. This can lead to unauthorized data access, "
                    "modification, or deletion."
                ),
                example="User input: ' OR '1'='1 -- could bypass login authentication",
            ),
            GlossaryEntry(
                term="Cross-Site Scripting (XSS)",
                definition=(
                    "A vulnerability where attackers can inject malicious scripts into web "
                    "pages viewed by other users. This can steal cookies, session tokens, "
                    "or perform actions on behalf of the victim."
                ),
                example="User input: <script>alert('hacked')</script> displayed on a page",
            ),
            GlossaryEntry(
                term="Parameterized Query",
                definition=(
                    "A query where user input is passed as parameters rather than "
                    "concatenated into the SQL string. The database treats parameters as "
                    "data, not code, preventing SQL injection."
                ),
                example="cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))",
            ),
            GlossaryEntry(
                term="Output Encoding/Escaping",
                definition=(
                    "Converting special characters in user input to their safe equivalents "
                    "before displaying them. This prevents the browser from interpreting "
                    "user input as HTML or JavaScript."
                ),
                example="< becomes &lt; so <script> becomes &lt;script&gt;",
            ),
            GlossaryEntry(
                term="True Positive",
                definition=(
                    "A security finding that represents a real vulnerability in the code. "
                    "These require remediation."
                ),
            ),
            GlossaryEntry(
                term="False Positive",
                definition=(
                    "A security finding that is incorrectly flagged as a vulnerability. "
                    "The code is actually safe, but the scanner couldn't determine this."
                ),
            ),
            GlossaryEntry(
                term="Stored XSS",
                definition=(
                    "XSS where the malicious script is permanently stored on the target "
                    "server (e.g., in a database) and served to users who view the page."
                ),
            ),
            GlossaryEntry(
                term="Reflected XSS",
                definition=(
                    "XSS where the malicious script is reflected off a web server in an "
                    "error message, search result, or any response that includes user input."
                ),
            ),
            GlossaryEntry(
                term="Input Validation",
                definition=(
                    "Checking user input to ensure it matches expected formats and values. "
                    "While helpful, it should be used alongside parameterization and encoding, "
                    "not as the only defense."
                ),
            ),
            GlossaryEntry(
                term="Principle of Least Privilege",
                definition=(
                    "A security principle where users and programs should only have the "
                    "minimum permissions needed to perform their tasks. Database users "
                    "should not have admin privileges for web applications."
                ),
            ),
        ]
