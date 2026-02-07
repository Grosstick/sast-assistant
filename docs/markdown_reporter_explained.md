# SAST Assistant - Complete Project Guide

Learn how to build an AI-powered security scanner from scratch. This guide explains every component of the project so you can understand and recreate it yourself.

---

## Table of Contents

1. [Project Overview](#project-overview)
2. [Architecture](#architecture)
3. [Project Structure](#project-structure)
4. [The Pipeline](#the-pipeline)
5. [Module Deep Dives](#module-deep-dives)
6. [Key Patterns Used](#key-patterns-used)
7. [How to Build Your Own](#how-to-build-your-own)

---

## Project Overview

**What this project does:**
1. Runs Semgrep (a security scanner) on your code
2. Extracts context around vulnerabilities found
3. Sends findings to Google Gemini AI for analysis
4. Generates educational Markdown reports

**Technologies used:**
- Python 3.10+
- Pydantic (data validation)
- Google Gemini API (AI analysis)
- Semgrep (security scanning)
- Rich (terminal UI)

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                              CLI (__main__.py)                          │
│                         User runs: sast-assistant scan                  │
└─────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                         4-STAGE PIPELINE                                │
├─────────────────┬─────────────────┬─────────────────┬───────────────────┤
│   1. Scanner    │   2. Extractor  │   3. AI Engine  │   4. Reporter     │
│                 │                 │                 │                   │
│  Run Semgrep    │  Get code       │  Analyze with   │  Generate         │
│  Parse JSON     │  context        │  Gemini LLM     │  Markdown         │
│  Filter rules   │  ±5 lines       │  Triage finds   │  Educational      │
└─────────────────┴─────────────────┴─────────────────┴───────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                            report.md                                    │
│               Human-readable security report for developers             │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Project Structure

```
sast-assistant/
├── pyproject.toml              # Project configuration & dependencies
├── README.md                   # User documentation
│
├── src/sast_assistant/
│   ├── __init__.py             # Package init, version info
│   ├── __main__.py             # CLI entry point (argparse)
│   ├── config.py               # Configuration classes
│   │
│   ├── models/                 # Pydantic data models
│   │   ├── semgrep.py          # Semgrep JSON output models
│   │   ├── finding.py          # Enriched finding models
│   │   └── report.py           # Report structure models
│   │
│   ├── scanner/                # Semgrep integration
│   │   └── semgrep.py          # Run Semgrep via subprocess
│   │
│   ├── extractor/              # Code context extraction
│   │   └── context.py          # Read files, extract lines
│   │
│   ├── ai_engine/              # LLM integration
│   │   ├── client.py           # Gemini API client
│   │   └── prompts.py          # System prompts
│   │
│   └── reporter/               # Report generation
│       └── markdown.py         # Markdown output
│
└── examples/                   # Sample vulnerable code for testing
    └── vulnerable_code/
        ├── python/vulnerable_app.py
        └── java/VulnerableApp.java
```

---

## The Pipeline

### Stage 1: Scanner (`scanner/semgrep.py`)

**Purpose:** Run Semgrep and parse its output

```python
class SemgrepScanner:
    def scan(self, target_path: str) -> SemgrepOutput:
        # 1. Build command
        cmd = [
            "semgrep", "scan",
            "--json",                    # Output as JSON
            "--config", "auto",          # Auto-detect rules
            target_path
        ]
        
        # 2. Run subprocess
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        # 3. Parse JSON output
        data = json.loads(result.stdout)
        
        # 4. Validate with Pydantic
        return SemgrepOutput.model_validate(data)
```

**Key concepts:**
- `subprocess.run()` - Execute external commands
- `capture_output=True` - Capture stdout/stderr
- Pydantic validation - Ensure data matches expected schema

---

### Stage 2: Context Extractor (`extractor/context.py`)

**Purpose:** Read vulnerable files and extract surrounding code

```python
class ContextExtractor:
    def __init__(self, lines_before: int = 5, lines_after: int = 5):
        self.lines_before = lines_before
        self.lines_after = lines_after
    
    def extract(self, file_path: str, line_number: int) -> CodeContext:
        # 1. Read the file
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        # 2. Calculate range (0-indexed)
        start = max(0, line_number - 1 - self.lines_before)
        end = min(len(lines), line_number + self.lines_after)
        
        # 3. Extract the slice
        context_lines = lines[start:end]
        
        # 4. Return structured data
        return CodeContext(
            file_path=file_path,
            start_line=start + 1,  # Convert back to 1-indexed
            end_line=end,
            lines=context_lines,
            vulnerable_line=line_number
        )
```

**Key concepts:**
- File I/O with context manager (`with open(...)`)
- `max()/min()` for bounds checking
- Line indexing (0-indexed vs 1-indexed)

---

### Stage 3: AI Engine (`ai_engine/client.py`)

**Purpose:** Send findings to Gemini for analysis

```python
class GeminiClient:
    def __init__(self, api_key: str):
        self.client = genai.Client(api_key=api_key)
    
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10)
    )
    def analyze(self, finding: EnrichedFinding) -> AIAnalysis:
        # 1. Build prompt
        prompt = self._build_prompt(finding)
        
        # 2. Call API
        response = self.client.models.generate_content(
            model="gemini-2.0-flash",
            contents=prompt
        )
        
        # 3. Parse JSON response
        return self._parse_response(response.text)
```

**Key concepts:**
- `@retry` decorator - Automatic retry with exponential backoff
- API client pattern - Wrap external API in clean interface
- Prompt engineering - Structured prompts for consistent output

---

### Stage 4: Reporter (`reporter/markdown.py`)

**Purpose:** Generate human-readable Markdown reports

```python
class MarkdownReporter:
    def generate_report(self, report: ScanReport) -> str:
        sections = []
        
        sections.append(self._render_header(report))
        sections.append(self._render_summary(report))
        
        for finding in report.findings:
            sections.append(self._render_finding(finding))
        
        sections.append(self._render_glossary(report.glossary))
        
        return "\n\n".join(sections)
```

**Key concepts:**
- Builder pattern - Accumulate sections in a list
- Private methods - `_render_*` for internal helpers
- String joining - `"\n\n".join()` for clean concatenation

---

## Module Deep Dives

### Models (`models/`)

Pydantic models define the shape of your data with automatic validation.

#### `models/semgrep.py` - Semgrep Output

```python
from pydantic import BaseModel

class SemgrepFinding(BaseModel):
    """Represents a single vulnerability found by Semgrep."""
    
    check_id: str           # Rule that matched (e.g., "python.sql-injection")
    path: str               # File path
    start: dict             # {"line": 10, "col": 5}
    end: dict               # {"line": 10, "col": 25}
    extra: dict             # Additional metadata (severity, message)
    
    @property
    def line_number(self) -> int:
        """Convenience property for the starting line."""
        return self.start.get("line", 0)
    
    @property
    def severity(self) -> str:
        """Extract severity from extra.metadata."""
        return self.extra.get("metadata", {}).get("severity", "WARNING")


class SemgrepOutput(BaseModel):
    """Complete Semgrep JSON output."""
    
    results: list[SemgrepFinding]
    errors: list[dict] = []
    
    def filter_by_rule_pattern(self, pattern: str) -> list[SemgrepFinding]:
        """Filter findings by rule ID pattern."""
        return [f for f in self.results if pattern in f.check_id]
```

**Why Pydantic?**
- Automatic JSON parsing: `SemgrepOutput.model_validate(json_data)`
- Type checking at runtime
- Easy serialization: `model.model_dump_json()`
- Self-documenting code

---

#### `models/finding.py` - Enriched Findings

```python
from enum import Enum

class VulnerabilityType(str, Enum):
    """Types of vulnerabilities we detect."""
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    OTHER = "other"


class TriageVerdict(str, Enum):
    """AI analysis verdict."""
    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    NEEDS_REVIEW = "needs_review"


class AIAnalysis(BaseModel):
    """Result from AI analysis of a finding."""
    
    verdict: TriageVerdict
    confidence: float           # 0.0 to 1.0
    explanation: str
    why_vulnerable: str | None
    risk_description: str | None
    attack_scenario: str | None
    suggested_fix: str | None
    fix_explanation: str | None
    security_principle: str | None
    common_mistakes: list[str] = []


class EnrichedFinding(BaseModel):
    """A finding with context and AI analysis."""
    
    file_path: str
    line_number: int
    rule_id: str
    severity: str
    vulnerability_type: VulnerabilityType
    context: CodeContext | None = None
    ai_analysis: AIAnalysis | None = None
    
    @classmethod
    def from_semgrep_finding(cls, finding: SemgrepFinding):
        """Factory method to create from Semgrep output."""
        return cls(
            file_path=finding.path,
            line_number=finding.line_number,
            rule_id=finding.check_id,
            severity=finding.severity,
            vulnerability_type=cls._detect_vuln_type(finding.check_id)
        )
    
    @staticmethod
    def _detect_vuln_type(rule_id: str) -> VulnerabilityType:
        """Detect vulnerability type from rule ID."""
        rule_lower = rule_id.lower()
        if "sql" in rule_lower:
            return VulnerabilityType.SQL_INJECTION
        elif "xss" in rule_lower or "cross-site" in rule_lower:
            return VulnerabilityType.XSS
        return VulnerabilityType.OTHER
```

**Key patterns:**
- `Enum` - Type-safe constants
- `str, Enum` - Enum that serializes as string
- `@classmethod` - Factory methods
- `@staticmethod` - Utility methods

---

### Configuration (`config.py`)

Use dataclasses or Pydantic for configuration with environment variable support.

```python
from dataclasses import dataclass, field
import os

@dataclass
class GeminiConfig:
    """Configuration for Gemini API."""
    
    api_key: str = field(default_factory=lambda: os.getenv("GEMINI_API_KEY", ""))
    model: str = "gemini-2.0-flash"
    temperature: float = 0.3
    timeout: int = 30
    
    def __post_init__(self):
        if not self.api_key:
            raise ValueError("GEMINI_API_KEY environment variable is required")


@dataclass  
class ScannerConfig:
    """Configuration for Semgrep scanner."""
    
    config: str = "auto"        # Semgrep config to use
    timeout: int = 300          # Max scan time in seconds
    exclude_patterns: list[str] = field(default_factory=list)


@dataclass
class AppConfig:
    """Main application configuration."""
    
    gemini: GeminiConfig = field(default_factory=GeminiConfig)
    scanner: ScannerConfig = field(default_factory=ScannerConfig)
    log_level: str = field(default_factory=lambda: os.getenv("SAST_LOG_LEVEL", "INFO"))
```

**Key patterns:**
- `@dataclass` - Auto-generate `__init__`, `__repr__`, etc.
- `field(default_factory=...)` - Lazy defaults
- `os.getenv()` - Environment variable access
- `__post_init__` - Validation after construction

---

### CLI Entry Point (`__main__.py`)

The `__main__.py` file makes your package runnable with `python -m sast_assistant`.

```python
import argparse
import sys
from rich.console import Console

from .scanner.semgrep import SemgrepScanner
from .extractor.context import ContextExtractor
from .ai_engine.client import GeminiClient
from .reporter.markdown import MarkdownReporter

console = Console()

def main():
    parser = argparse.ArgumentParser(
        prog="sast-assistant",
        description="AI-powered security scanner"
    )
    
    subparsers = parser.add_subparsers(dest="command", required=True)
    
    # scan command
    scan_parser = subparsers.add_parser("scan", help="Scan code for vulnerabilities")
    scan_parser.add_argument("target", help="Path to scan")
    scan_parser.add_argument("--output", "-o", help="Output report path")
    scan_parser.add_argument("--no-ai", action="store_true", help="Skip AI analysis")
    
    # verify command
    verify_parser = subparsers.add_parser("verify", help="Verify dependencies")
    
    args = parser.parse_args()
    
    if args.command == "scan":
        run_scan(args)
    elif args.command == "verify":
        run_verify(args)


def run_scan(args):
    """Execute the scan pipeline."""
    with console.status("[bold green]Running scan..."):
        # Stage 1: Scan
        scanner = SemgrepScanner()
        semgrep_output = scanner.scan(args.target)
        
        # Stage 2: Extract context
        extractor = ContextExtractor()
        findings = []
        for result in semgrep_output.results:
            finding = EnrichedFinding.from_semgrep_finding(result)
            finding.context = extractor.extract(finding.file_path, finding.line_number)
            findings.append(finding)
        
        # Stage 3: AI analysis (optional)
        if not args.no_ai:
            client = GeminiClient()
            for finding in findings:
                finding.ai_analysis = client.analyze(finding)
        
        # Stage 4: Generate report
        reporter = MarkdownReporter()
        report = ScanReport.from_enriched_findings(findings, args.target)
        reporter.save_report(report, args.output or "report.md")
    
    console.print("[bold green]✓ Scan complete!")


if __name__ == "__main__":
    main()
```

**Key concepts:**
- `argparse` - Standard library for CLI parsing
- Subcommands - `scan`, `verify`, etc.
- `console.status()` - Rich progress indicator
- Pipeline orchestration - Wire components together

---

### AI Prompts (`ai_engine/prompts.py`)

Well-crafted prompts are essential for good AI output.

```python
SYSTEM_PROMPT = """You are a security expert helping junior developers understand vulnerabilities.

For each finding, analyze the code and provide:
1. Whether it's a true positive (real vulnerability) or false positive
2. Why the code is vulnerable (in simple terms)
3. The potential risk if exploited
4. A realistic attack scenario
5. A corrected version of the code
6. The security principle being violated

Be educational and encouraging. Use analogies when helpful.
Respond in JSON format with this structure:

{
    "verdict": "true_positive" | "false_positive" | "needs_review",
    "confidence": 0.0-1.0,
    "why_vulnerable": "explanation...",
    "risk_description": "what could happen...",
    "attack_scenario": "step by step attack...",
    "suggested_fix": "corrected code...",
    "fix_explanation": "what changed and why...",
    "security_principle": "the rule being violated...",
    "common_mistakes": ["mistake 1", "mistake 2"]
}"""


def build_analysis_prompt(finding: EnrichedFinding) -> str:
    """Build a prompt for AI analysis of a specific finding."""
    
    context = ""
    if finding.context:
        context = f"""
Code context (line {finding.context.start_line} to {finding.context.end_line}):
```{finding.context.get_language()}
{finding.context.get_formatted_code()}
```
"""
    
    return f"""{SYSTEM_PROMPT}

---

Analyze this security finding:

Rule: {finding.rule_id}
File: {finding.file_path}
Line: {finding.line_number}
Severity: {finding.severity}
Type: {finding.vulnerability_type.value}

{context}

Provide your analysis in JSON format."""
```

---

## Key Patterns Used

### 1. Factory Methods

Create objects from different sources:

```python
class EnrichedFinding(BaseModel):
    @classmethod
    def from_semgrep_finding(cls, finding: SemgrepFinding):
        return cls(
            file_path=finding.path,
            line_number=finding.line_number,
            # ... map fields
        )
```

### 2. Builder Pattern

Accumulate parts and combine:

```python
sections = []
sections.append(render_header())
sections.append(render_body())
return "\n".join(sections)
```

### 3. Dependency Injection

Pass dependencies instead of hardcoding:

```python
class MarkdownReporter:
    def __init__(self, config: ReporterConfig = None):
        self.config = config or ReporterConfig()
```

### 4. Retry with Exponential Backoff

Handle transient failures:

```python
@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(min=2, max=10)
)
def call_api():
    ...
```

### 5. Context Managers

Clean resource handling:

```python
with open(file_path, 'r') as f:
    content = f.read()
```

### 6. Enums for Type Safety

Prevent typos and enable autocomplete:

```python
class Severity(str, Enum):
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"
```

---

## How to Build Your Own

### Step 1: Define Your Data Models

Start by defining what data flows through your system:

```python
# What comes in from external tools?
class ExternalToolOutput(BaseModel):
    ...

# What do you enrich it with?
class EnrichedData(BaseModel):
    ...

# What does your output look like?
class ReportData(BaseModel):
    ...
```

### Step 2: Build Individual Components

Each component should:
- Have a single responsibility
- Accept configuration via constructor
- Return Pydantic models

### Step 3: Wire Components in CLI

The CLI orchestrates the pipeline:

```python
def main():
    # 1. Parse args
    # 2. Initialize components
    # 3. Run pipeline stages
    # 4. Output results
```

### Step 4: Add Error Handling

Wrap external calls with try/except:

```python
try:
    result = scanner.scan(target)
except ScanError as e:
    console.print(f"[red]Error: {e}")
    sys.exit(1)
```

### Step 5: Add Configuration

Support environment variables and CLI flags:

```python
@dataclass
class Config:
    api_key: str = field(default_factory=lambda: os.getenv("API_KEY"))
```

---

## Exercises

1. **Add a new scanner**: Integrate Bandit instead of Semgrep
2. **Add HTML output**: Create `HTMLReporter` alongside `MarkdownReporter`
3. **Add caching**: Cache AI responses to avoid duplicate API calls
4. **Add severity filtering**: Only report HIGH/CRITICAL findings
5. **Add metrics**: Track scan time, findings per file, etc.

---

## Files to Study (In Order)

1. `pyproject.toml` - See how dependencies are declared
2. `config.py` - Understand configuration patterns
3. `models/semgrep.py` - Learn Pydantic basics
4. `scanner/semgrep.py` - See subprocess usage
5. `extractor/context.py` - File I/O patterns
6. `ai_engine/client.py` - API integration
7. `reporter/markdown.py` - Report generation
8. `__main__.py` - CLI and orchestration

Good luck building your own tools! 🚀
