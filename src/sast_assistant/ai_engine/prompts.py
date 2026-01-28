"""Educational prompts for AI triage analysis."""

from ..models.finding import VulnerabilityType


SYSTEM_PROMPT = """You are a senior security engineer mentoring junior developers. Your role is to analyze code flagged by automated security scanners and provide clear, educational explanations that help developers understand and fix security vulnerabilities.

## Your Responsibilities

1. **Analyze the vulnerability**: Determine if the flagged code is a true positive (real vulnerability), false positive (safe code), or needs more context.

2. **Explain clearly**: Use simple language and analogies to explain why the code is vulnerable. Avoid jargon without explanation.

3. **Provide actionable fixes**: Give specific, language-appropriate code fixes that the developer can apply directly.

4. **Teach security principles**: Help developers understand the underlying security concept so they can recognize similar issues in the future.

## Guidelines

- Always consider the context around the vulnerable line
- Look for existing sanitization, parameterization, or encoding that might make the code safe
- Be specific about what makes the code vulnerable
- Explain the attack scenario in practical terms
- Provide fixes that maintain the code's functionality
- NEVER suggest fixes that introduce new vulnerabilities
- Use the correct syntax for the programming language being analyzed
- For Java, recommend PreparedStatement over Statement for SQL queries
- For Python, recommend parameterized queries using ? or named parameters
- For XSS, recommend context-appropriate encoding (HTML entities, JavaScript escaping, URL encoding)

## Output Format

You MUST respond in valid JSON format with these fields:
{
  "verdict": "true_positive" | "false_positive" | "needs_review",
  "confidence": 0.0 to 1.0,
  "explanation": "Brief summary of the finding",
  "why_vulnerable": "Clear explanation of why this code is vulnerable (or why it's safe for false positives)",
  "risk_description": "What could happen if this vulnerability is exploited",
  "suggested_fix": "The fixed code snippet",
  "fix_explanation": "Step-by-step explanation of what changed and why",
  "security_principle": "The underlying security principle (e.g., 'Never trust user input')",
  "common_mistakes": ["List of related mistakes developers often make"],
  "attack_scenario": "A concrete example of how an attacker could exploit this"
}"""


SQL_INJECTION_CONTEXT = """
## SQL Injection Context

You are analyzing code flagged for potential SQL injection vulnerability.

**What is SQL Injection?**
SQL injection occurs when user input is directly incorporated into SQL queries without proper sanitization or parameterization. Attackers can manipulate the query structure to:
- Bypass authentication
- Extract sensitive data
- Modify or delete data
- Execute administrative operations

**What to look for:**
- String concatenation in SQL queries: `"SELECT * FROM users WHERE id = " + userId`
- String formatting with user input: `f"SELECT * FROM users WHERE id = {user_id}"`
- Missing use of parameterized queries (PreparedStatement in Java, ? placeholders in Python)

**Safe patterns:**
- **Java**: `PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?"); ps.setInt(1, userId);`
- **Python**: `cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))`
- **Python with SQLAlchemy**: Using ORM methods or `text()` with `bindparams`

**Common False Positives:**
- Hardcoded SQL without user input
- Queries where the "variable" is actually a constant or enum
- Properly parameterized queries that the scanner couldn't recognize
"""


XSS_CONTEXT = """
## Cross-Site Scripting (XSS) Context

You are analyzing code flagged for potential XSS vulnerability.

**What is XSS?**
Cross-Site Scripting occurs when user-controlled data is included in web page output without proper encoding. Attackers can inject malicious scripts that:
- Steal session cookies and authentication tokens
- Perform actions on behalf of the user
- Redirect users to malicious sites
- Deface web pages

**Types of XSS:**
- **Reflected XSS**: Malicious script comes from the current HTTP request
- **Stored XSS**: Malicious script is stored in the database and served to other users
- **DOM-based XSS**: Vulnerability exists in client-side JavaScript

**What to look for:**
- Directly outputting user input in HTML: `response.write(userInput)`
- Missing output encoding in templates
- Using `innerHTML` or similar with user data
- Unsafe string concatenation in HTML responses

**Safe patterns:**
- **Java**: Use OWASP encoder: `Encode.forHtml(userInput)`, or framework auto-escaping
- **Python/Flask**: Use `| e` filter in Jinja2: `{{ user_input | e }}`
- **Python/Django**: Auto-escaping is enabled by default
- **General**: Use Content-Security-Policy headers

**Context-specific encoding:**
- HTML content: HTML entity encoding (`<` → `&lt;`)
- HTML attributes: Attribute encoding with quotes
- JavaScript: JavaScript encoding or JSON serialization
- URLs: URL encoding (`encodeURIComponent`)

**Common False Positives:**
- Output that goes through template auto-escaping
- Static content without user input
- Data that's properly sanitized before storage
"""


OTHER_VULNERABILITY_CONTEXT = """
## Security Vulnerability Analysis

You are analyzing code flagged for a potential security vulnerability.

**General Security Principles:**
1. Never trust user input
2. Validate and sanitize all external data
3. Use the principle of least privilege
4. Implement defense in depth
5. Fail securely

**When analyzing:**
- Check if user input reaches the vulnerable sink
- Look for existing validation or sanitization
- Consider the data flow from source to sink
- Evaluate the severity based on the attack surface
"""


def get_analysis_prompt(
    code_context: str,
    rule_id: str,
    vulnerability_type: VulnerabilityType,
    language: str,
    message: str,
) -> str:
    """
    Generate the user prompt for vulnerability analysis.
    
    Args:
        code_context: The formatted code snippet with line numbers
        rule_id: The Semgrep rule ID that triggered
        vulnerability_type: Type of vulnerability (SQLi, XSS, other)
        language: Programming language (java, python, etc.)
        message: The original Semgrep message
        
    Returns:
        Formatted prompt for the LLM
    """
    # Select appropriate context based on vulnerability type
    if vulnerability_type == VulnerabilityType.SQL_INJECTION:
        vuln_context = SQL_INJECTION_CONTEXT
    elif vulnerability_type == VulnerabilityType.XSS:
        vuln_context = XSS_CONTEXT
    else:
        vuln_context = OTHER_VULNERABILITY_CONTEXT
    
    return f"""{vuln_context}

## Finding Details

**Rule ID**: {rule_id}
**Language**: {language.upper()}
**Scanner Message**: {message}

## Code to Analyze

The line marked with `>>>` is the flagged vulnerable line:

```{language}
{code_context}
```

## Your Task

Analyze this code and determine:
1. Is this a true positive (real vulnerability) or false positive (safe code)?
2. If vulnerable, explain why in terms a junior developer would understand
3. Provide a specific fix with corrected code
4. Teach the security principle involved

Remember: Respond ONLY with valid JSON matching the required format."""


def get_batch_analysis_prompt(findings_data: list[dict]) -> str:
    """
    Generate a prompt for batch analysis of multiple findings.
    
    Args:
        findings_data: List of dicts with code_context, rule_id, vuln_type, language, message
        
    Returns:
        Formatted prompt for batch analysis
    """
    prompt_parts = [
        "Analyze the following security findings. For each finding, provide a JSON analysis.",
        "Respond with a JSON array where each element corresponds to a finding.",
        "",
        "---",
    ]
    
    for i, finding in enumerate(findings_data, start=1):
        vuln_type = finding.get("vulnerability_type", VulnerabilityType.OTHER)
        if vuln_type == VulnerabilityType.SQL_INJECTION:
            vuln_context = "SQL Injection"
        elif vuln_type == VulnerabilityType.XSS:
            vuln_context = "XSS"
        else:
            vuln_context = "Security"
        
        prompt_parts.append(f"""
## Finding {i}: {vuln_context}

**Rule**: {finding.get('rule_id', 'unknown')}
**Language**: {finding.get('language', 'unknown').upper()}
**Message**: {finding.get('message', '')}

```{finding.get('language', '')}
{finding.get('code_context', '')}
```
""")
    
    prompt_parts.append("""
---

Respond with a JSON array of analyses, one for each finding above.
Each analysis must have: verdict, confidence, explanation, why_vulnerable, risk_description, 
suggested_fix, fix_explanation, security_principle, common_mistakes, attack_scenario.""")
    
    return "\n".join(prompt_parts)
