"""Semgrep scanner integration via subprocess.

Runs Semgrep CLI and parses JSON output.
Subprocess usage based on: https://realpython.com/python-subprocess/
"""

import json
import logging
import subprocess
from pathlib import Path
from typing import Optional

from ..config import SemgrepConfig
from ..models.semgrep import SemgrepResult, SemgrepFinding

logger = logging.getLogger(__name__)


class SemgrepScanError(Exception):
    """Exception raised when Semgrep scan fails."""
    
    def __init__(self, message: str, return_code: int = -1, stderr: str = ""):
        super().__init__(message)
        self.return_code = return_code
        self.stderr = stderr


class SemgrepScanner:
    """Scanner that integrates with Semgrep via subprocess."""
    
    def __init__(self, config: Optional[SemgrepConfig] = None):
        self.config = config or SemgrepConfig()
        self._binary_path: Optional[str] = None
    
    @property
    def binary_path(self) -> str:
        if self._binary_path is None:
            self._binary_path = self.config.get_binary_path()
        return self._binary_path
    
    def scan(self, target_path: str | Path) -> SemgrepResult:
        """Run Semgrep scan on the target path."""
        target = Path(target_path)
        
        if not target.exists():
            raise FileNotFoundError(f"Target path does not exist: {target}")
        
        logger.info(f"Starting Semgrep scan on: {target}")
        
        cmd = self._build_command(target)
        logger.debug(f"Running command: {' '.join(cmd)}")
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.config.timeout,
            )
            
            if result.returncode not in (0, 1):
                raise SemgrepScanError(
                    f"Semgrep scan failed with return code {result.returncode}",
                    return_code=result.returncode,
                    stderr=result.stderr,
                )
            
            return self._parse_output(result.stdout)
            
        except subprocess.TimeoutExpired:
            raise SemgrepScanError(f"Semgrep scan timed out after {self.config.timeout} seconds")
        except FileNotFoundError:
            raise SemgrepScanError(
                f"Semgrep binary not found at: {self.binary_path}\n"
                "Please install Semgrep: pip install semgrep"
            )
        except json.JSONDecodeError as e:
            raise SemgrepScanError(f"Failed to parse Semgrep output: {e}")
    
    def _build_command(self, target: Path) -> list[str]:
        cmd = [
            self.binary_path,
            "scan",
            "--json",
            "--no-git-ignore",
        ]
        
        if self.config.config:
            cmd.extend(["--config", self.config.config])
        
        cmd.append(str(target.absolute()))
        return cmd
    
    def _parse_output(self, output: str) -> SemgrepResult:
        if not output.strip():
            logger.warning("Semgrep returned empty output")
            return SemgrepResult()
        
        try:
            data = json.loads(output)
            result = SemgrepResult.model_validate(data)
            
            logger.info(f"Scan complete: {result.finding_count} findings, {result.error_count} errors")
            
            severity_summary = result.get_severity_summary()
            if severity_summary:
                logger.info(f"Severity breakdown: {severity_summary}")
            
            return result
            
        except Exception as e:
            logger.error(f"Failed to parse Semgrep output: {e}")
            raise SemgrepScanError(f"Failed to parse Semgrep output: {e}")
    
    def scan_for_sqli_and_xss(self, target_path: str | Path) -> SemgrepResult:
        """Run Semgrep scan and filter for SQL injection and XSS findings only."""
        full_result = self.scan(target_path)
        
        sqli_findings = full_result.get_sql_injection_findings()
        xss_findings = full_result.get_xss_findings()
        filtered_findings = sqli_findings + xss_findings
        
        seen_ids = set()
        unique_findings: list[SemgrepFinding] = []
        for f in filtered_findings:
            finding_id = (f.path, f.start.line, f.check_id)
            if finding_id not in seen_ids:
                seen_ids.add(finding_id)
                unique_findings.append(f)
        
        return SemgrepResult(
            results=unique_findings,
            errors=full_result.errors,
            version=full_result.version,
        )
    
    def verify_installation(self) -> tuple[bool, str]:
        """Verify that Semgrep is properly installed."""
        try:
            result = subprocess.run(
                [self.binary_path, "--version"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            
            if result.returncode == 0:
                return True, result.stdout.strip()
            else:
                return False, f"Semgrep returned error: {result.stderr}"
                
        except FileNotFoundError:
            return False, "Semgrep binary not found. Install with: pip install semgrep"
        except subprocess.TimeoutExpired:
            return False, "Semgrep version check timed out"
        except Exception as e:
            return False, f"Error checking Semgrep: {e}"
