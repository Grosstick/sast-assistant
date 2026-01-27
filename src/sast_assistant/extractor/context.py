"""Code context extraction for vulnerability findings.

Extracts code snippets around vulnerable lines for AI analysis.
File reading approach based on: https://realpython.com/read-write-files-python/
"""

import logging
from pathlib import Path
from typing import Optional

from ..config import ContextConfig
from ..models.semgrep import SemgrepFinding
from ..models.finding import CodeContext

logger = logging.getLogger(__name__)


class ContextExtractionError(Exception):
    """Exception raised when context extraction fails."""
    pass


class ContextExtractor:
    """Extracts code context surrounding vulnerability findings."""
    
    def __init__(self, config: Optional[ContextConfig] = None):
        self.config = config or ContextConfig()
    
    def extract_context(self, finding: SemgrepFinding) -> CodeContext:
        """Extract code context for a single finding."""
        file_path = Path(finding.path)
        
        if not file_path.exists():
            raise ContextExtractionError(f"Source file not found: {file_path}")
        
        if file_path.stat().st_size > self.config.max_file_size_bytes:
            logger.warning(f"File too large for context extraction: {file_path}")
        
        try:
            return self._read_context(file_path, finding.line_number)
        except Exception as e:
            raise ContextExtractionError(f"Failed to extract context: {e}")
    
    def _read_context(self, file_path: Path, vulnerable_line: int) -> CodeContext:
        """Read the source file and extract context around the vulnerable line."""
        try:
            try:
                content = file_path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                content = file_path.read_text(encoding="latin-1")
                logger.warning(f"File {file_path} read with latin-1 fallback encoding")
        except Exception as e:
            raise ContextExtractionError(f"Failed to read file {file_path}: {e}")
        
        lines = content.splitlines()
        total_lines = len(lines)
        
        if total_lines == 0:
            return CodeContext(
                file_path=str(file_path),
                vulnerable_line=vulnerable_line,
                start_line=1,
                end_line=1,
                code_lines=[],
            )
        
        if vulnerable_line > total_lines:
            logger.warning(f"Vulnerability line {vulnerable_line} exceeds file length {total_lines}")
            vulnerable_line = total_lines
        
        start_line = max(1, vulnerable_line - self.config.lines_before)
        end_line = min(total_lines, vulnerable_line + self.config.lines_after)
        extracted_lines = lines[start_line - 1 : end_line]
        
        logger.debug(f"Extracted context for {file_path}:{vulnerable_line} (lines {start_line}-{end_line})")
        
        return CodeContext(
            file_path=str(file_path),
            vulnerable_line=vulnerable_line,
            start_line=start_line,
            end_line=end_line,
            code_lines=extracted_lines,
        )
    
    def extract_context_batch(self, findings: list[SemgrepFinding]) -> dict[str, CodeContext]:
        """Extract context for multiple findings, grouping by file to minimize reads."""
        results: dict[str, CodeContext] = {}
        
        findings_by_file: dict[str, list[SemgrepFinding]] = {}
        for finding in findings:
            if finding.path not in findings_by_file:
                findings_by_file[finding.path] = []
            findings_by_file[finding.path].append(finding)
        
        for file_path, file_findings in findings_by_file.items():
            try:
                path = Path(file_path)
                if not path.exists():
                    logger.warning(f"File not found, skipping: {file_path}")
                    continue
                
                try:
                    content = path.read_text(encoding="utf-8")
                except UnicodeDecodeError:
                    content = path.read_text(encoding="latin-1")
                
                lines = content.splitlines()
                total_lines = len(lines)
                
                for finding in file_findings:
                    finding_id = self._get_finding_id(finding)
                    
                    try:
                        vulnerable_line = min(finding.line_number, total_lines)
                        start_line = max(1, vulnerable_line - self.config.lines_before)
                        end_line = min(total_lines, vulnerable_line + self.config.lines_after)
                        
                        results[finding_id] = CodeContext(
                            file_path=str(path),
                            vulnerable_line=vulnerable_line,
                            start_line=start_line,
                            end_line=end_line,
                            code_lines=lines[start_line - 1 : end_line],
                        )
                    except Exception as e:
                        logger.warning(f"Failed to extract context for {finding_id}: {e}")
                        
            except Exception as e:
                logger.warning(f"Failed to process file {file_path}: {e}")
        
        logger.info(f"Extracted context for {len(results)}/{len(findings)} findings")
        return results
    
    @staticmethod
    def _get_finding_id(finding: SemgrepFinding) -> str:
        return f"{finding.path}:{finding.line_number}:{finding.check_id}"
