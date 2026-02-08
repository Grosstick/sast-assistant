# SAST Assistant

> AI-powered Static Application Security Testing assistant combining Semgrep with LLM-based analysis

SAST Assistant is a "Scan-Enrich-Fix" pipeline that helps junior developers understand and fix security vulnerabilities in their code. It combines the speed of automated scanning with the educational power of AI explanations.

## Features

- **Semgrep Integration**: Leverages Semgrep's powerful rule engine for vulnerability detection
- **AI-Powered Analysis**: Uses Google Gemini to explain vulnerabilities in educational terms
- **Educational Reports**: Generates Markdown reports with step-by-step explanations
- **Focused Detection**: Specializes in SQL injection and XSS vulnerabilities
- **Multi-Language**: Supports Java and Python codebases

## Installation

### Prerequisites

- Python 3.10 or higher
- Semgrep CLI
- Google Gemini API key

### Install Semgrep

```bash
pip install semgrep
```

Or on macOS:
```bash
brew install semgrep
```

### Install SAST Assistant

```bash
cd sast-assistant
pip install -e .
```

### Set up API Key

```bash
# Linux/macOS
export GEMINI_API_KEY=your-api-key-here

# Windows
set GEMINI_API_KEY=your-api-key-here
```

## Usage

### Basic Scan

```bash
sast-assistant scan ./src --output report.md
```

### Scan without AI Analysis

```bash
sast-assistant scan ./src --no-ai --output report.md
```

### Filter for SQL Injection and XSS Only

```bash
sast-assistant scan ./src --sqli-xss-only --output report.md
```

### Verify Installation

```bash
sast-assistant verify
```

### Output as JSON

```bash
sast-assistant scan ./src --json --output findings.json
```

## Example Output

The generated Markdown report includes:

1. **Executive Summary** - Overview of findings with severity breakdown
2. **Findings Table** - Quick reference of all vulnerabilities
3. **Detailed Findings** - For each vulnerability:
   - Code context with line numbers
   - AI explanation of why the code is vulnerable
   - Risk assessment
   - Suggested fix with explanation
   - Security principles involved
4. **Security Glossary** - Definitions of security terms

## Configuration

Configuration can be set via environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `GEMINI_API_KEY` | Google Gemini API key | Required |
| `SAST_LOG_LEVEL` | Logging level (DEBUG, INFO, WARNING, ERROR) | INFO |
| `SAST_CONTEXT_LINES` | Lines of context above/below vulnerable code | 5 |
| `SAST_GEMINI_MODEL` | Gemini model to use | gemini-2.0-flash |
| `SAST_BATCH_SIZE` | Findings to analyze per batch | 10 |

## Project Structure

```
sast-assistant/
├── src/sast_assistant/
│   ├── __init__.py          # Package init
│   ├── __main__.py           # CLI entry point
│   ├── config.py             # Configuration management
│   ├── models/               # Pydantic data models
│   │   ├── semgrep.py        # Semgrep output models
│   │   ├── finding.py        # Enriched finding models
│   │   └── report.py         # Report models
│   ├── scanner/              # Semgrep integration
│   │   └── semgrep.py        # Subprocess-based scanner
│   ├── extractor/            # Code context extraction
│   │   └── context.py        # Context extractor
│   ├── ai_engine/            # AI analysis
│   │   ├── client.py         # Gemini API client
│   │   └── prompts.py        # Educational prompts
│   └── reporter/             # Report generation
│       └── markdown.py       # Markdown reporter
└── examples/
    └── vulnerable_code/      # Sample vulnerable code for testing
        ├── java/
        └── python/
```

## Pipeline Architecture

```
┌─────────────┐     ┌──────────────┐    ┌────────────┐     ┌──────────────┐
│   Scanner   │───▶│  Extractor   │───▶│ AI Engine  │───▶│   Reporter   │
│  (Semgrep)  │     │  (Context)   │    │  (Gemini)  │     │  (Markdown)  │
└─────────────┘     └──────────────┘    └────────────┘     └──────────────┘
     │                   │                   │                   │
     ▼                   ▼                   ▼                   ▼
  JSON output      Code snippets       AI analysis         .md report
  with findings    with 5 lines       explanations        for developers
                   above/below        and fixes
```

## Testing with Sample Code

The `examples/vulnerable_code/` directory contains intentionally vulnerable code for testing:

```bash
# Scan the Python examples
sast-assistant scan examples/vulnerable_code/python --output python_report.md

# Scan the Java examples
sast-assistant scan examples/vulnerable_code/java --output java_report.md
```

## License

MIT License
