"""Markdown report generator for SAST findings.

Generates educational security reports in Markdown format.
String formatting learned from: https://realpython.com/python-f-strings/
"""

import logging
from pathlib import Path
from typing import Optional

from ..config import ReporterConfig
from ..models.report import ScanReport, FindingReport, GlossaryEntry
from ..models.finding import EnrichedFinding, TriageVerdict, VulnerabilityType

logger = logging.getLogger(__name__)


# TODO: might want to make these configurable
SEVERITY_EMOJIS = {"ERROR": "🔴", "WARNING": "🟡", "INFO": "🔵"}


class MarkdownReporter:
    """Generates educational Markdown reports from scan results."""
    
    def __init__(self, config: Optional[ReporterConfig] = None):
        self.config = config or ReporterConfig()
    
    def _strip_code_fences(self, text: str) -> str:
        """Strip markdown code fences to prevent nested blocks."""
        text = text.strip()
        
        if text.startswith("```"):
            first_newline = text.find("\n")
            if first_newline != -1:
                text = text[first_newline + 1:]
        
        if text.rstrip().endswith("```"):
            text = text.rstrip()[:-3].rstrip()
        
        return text
    
    def generate_report(self, report: ScanReport) -> str:
        """Generate a complete Markdown report."""
        sections = []
        
        sections.append(self._render_header(report))
        
        if self.config.include_summary:
            sections.append(self._render_summary(report))
        
        if report.findings:
            sections.append(self._render_findings_table(report))
        
        for finding_report in report.findings:
            sections.append(self._render_finding(finding_report))
        
        if self.config.include_glossary and report.glossary:
            sections.append(self._render_glossary(report.glossary))
        
        return "\n\n".join(sections)
    
    def _render_header(self, report: ScanReport) -> str:
        return f"""# {report.title}

**Generated**: {report.generated_at.strftime('%Y-%m-%d %H:%M:%S')}  
**Target**: `{report.target_path}`  
**SAST Assistant Version**: {report.sast_assistant_version or '1.0.0'}  
**Semgrep Version**: {report.semgrep_version or 'N/A'}"""
    
    def _render_summary(self, report: ScanReport) -> str:
        s = report.summary
        
        severity_parts = []
        if s.by_severity.error > 0:
            severity_parts.append(f"🔴 {s.by_severity.error} Critical/Error")
        if s.by_severity.warning > 0:
            severity_parts.append(f"🟡 {s.by_severity.warning} Warning")
        if s.by_severity.info > 0:
            severity_parts.append(f"🔵 {s.by_severity.info} Info")
        severity_text = " | ".join(severity_parts) if severity_parts else "No findings"
        
        vuln_parts = []
        if s.by_type.sql_injection > 0:
            vuln_parts.append(f"💉 {s.by_type.sql_injection} SQL Injection")
        if s.by_type.xss > 0:
            vuln_parts.append(f"🌐 {s.by_type.xss} XSS")
        if s.by_type.other > 0:
            vuln_parts.append(f"🔒 {s.by_type.other} Other")
        vuln_text = " | ".join(vuln_parts) if vuln_parts else "None detected"
        
        verdict_text = ""
        if s.ai_analysis_enabled:
            verdict_parts = []
            if s.by_verdict.true_positive > 0:
                verdict_parts.append(f"⚠️ {s.by_verdict.true_positive} True Positives")
            if s.by_verdict.false_positive > 0:
                verdict_parts.append(f"✅ {s.by_verdict.false_positive} False Positives")
            if s.by_verdict.needs_review > 0:
                verdict_parts.append(f"🔍 {s.by_verdict.needs_review} Need Review")
            verdict_text = "\n**AI Triage**: " + (" | ".join(verdict_parts) if verdict_parts else "Not analyzed")
        
        return f"""## 📊 Executive Summary

**Total Findings**: {s.total_findings} across {s.files_with_findings} files  
**Scan Duration**: {s.scan_duration_seconds:.2f} seconds

### Severity Breakdown
{severity_text}

### Vulnerability Types
{vuln_text}
{verdict_text}

---"""
    
    def _render_findings_table(self, report: ScanReport) -> str:
        rows = ["## 📋 Findings Overview", "", "| # | Severity | Type | File | Line | Verdict |",
                "|---|----------|------|------|------|---------|"]
        
        for fr in report.findings:
            f = fr.finding
            verdict = fr.get_verdict_emoji() if f.ai_analysis else "❓"
            vuln_type = f.vulnerability_type.value.replace("_", " ").title()
            severity = fr.get_severity_emoji()
            
            file_path = f.file_path
            if len(file_path) > 40:
                file_path = "..." + file_path[-37:]
            
            rows.append(f"| {fr.section_number} | {severity} | {vuln_type} | `{file_path}` | {f.line_number} | {verdict} |")
        
        rows.extend(["", "---"])
        return "\n".join(rows)
    
    def _render_finding(self, finding_report: FindingReport) -> str:
        f = finding_report.finding
        num = finding_report.section_number
        severity_emoji = finding_report.get_severity_emoji()
        verdict_emoji = finding_report.get_verdict_emoji()
        
        vuln_type = f.vulnerability_type.value.replace("_", " ").title()
        header = f"## {severity_emoji} Finding #{num}: {vuln_type}"
        
        info = f"""**File**: `{f.file_path}`  
**Line**: {f.line_number}  
**Rule ID**: `{f.rule_id}`  
**Severity**: {f.severity}"""
        
        code_section = ""
        if f.context:
            lang = f.context.get_language()
            code = f.context.get_formatted_code(include_line_numbers=True)
            code_section = f"""
### 📝 Vulnerable Code

```{lang}
{code}
```"""
        
        ai_section = ""
        if f.ai_analysis:
            ai = f.ai_analysis
            verdict_text = ai.verdict.value.replace("_", " ").title()
            
            ai_section = f"""
### 🤖 AI Analysis

**Verdict**: {verdict_emoji} {verdict_text} (Confidence: {ai.confidence:.0%})

#### Why This Code Is Vulnerable

{ai.why_vulnerable or ai.explanation or "_No explanation available_"}

#### Risk

{ai.risk_description or "_Not assessed_"}

#### Attack Scenario

{ai.attack_scenario or "_Not provided_"}"""
            
            if ai.verdict == TriageVerdict.TRUE_POSITIVE and ai.suggested_fix:
                lang = f.context.get_language() if f.context else ""
                fix_code = self._strip_code_fences(ai.suggested_fix)
                ai_section += f"""

### ✅ Suggested Fix

```{lang}
{fix_code}
```

**What Changed**: {ai.fix_explanation or "_Explanation not provided_"}"""
            
            if ai.security_principle:
                ai_section += f"""

### 📚 Security Principle

> {ai.security_principle}"""
            
            if ai.common_mistakes:
                mistakes = "\n".join(f"- {m}" for m in ai.common_mistakes)
                ai_section += f"""

### ⚠️ Common Mistakes to Avoid

{mistakes}"""
        
        else:
            ai_section = """
### 🤖 AI Analysis

_AI analysis was not performed for this finding._"""
        
        return f"""{header}

{info}
{code_section}
{ai_section}

---"""
    
    def _render_glossary(self, glossary: list[GlossaryEntry]) -> str:
        lines = ["## 📖 Security Glossary", "", "_Definitions for junior developers:_", ""]
        
        for entry in glossary:
            lines.append(f"### {entry.term}")
            lines.append("")
            lines.append(entry.definition)
            if entry.example:
                lines.append("")
                lines.append(f"**Example**: `{entry.example}`")
            lines.append("")
        
        return "\n".join(lines)
    
    def save_report(self, report: ScanReport, output_path: str | Path) -> None:
        """Generate and save the report to a file."""
        content = self.generate_report(report)
        
        output = Path(output_path)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(content, encoding="utf-8")
        
        logger.info(f"Report saved to: {output}")


def generate_markdown_report(
    findings: list[EnrichedFinding],
    target_path: str,
    output_path: str | Path,
    scan_duration: float = 0.0,
    ai_enabled: bool = True,
) -> str:
    """Convenience function to generate and save a Markdown report."""
    report = ScanReport.from_enriched_findings(
        findings=findings,
        target_path=target_path,
        scan_duration=scan_duration,
        ai_enabled=ai_enabled,
    )
    
    reporter = MarkdownReporter()
    reporter.save_report(report, output_path)
    
    return str(output_path)
