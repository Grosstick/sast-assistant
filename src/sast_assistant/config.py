"""Configuration management for SAST Assistant.

Based on: https://realpython.com/python-data-classes/
Using dataclasses for config management - cleaner than raw dicts
"""

import os
import shutil
import logging
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class SemgrepConfig:
    """Configuration for Semgrep scanner."""
    
    binary_path: Optional[str] = None
    config: str = "auto"
    timeout: int = 300
    max_target_bytes: int = 10_000_000
    
    def get_binary_path(self) -> str:
        if self.binary_path:
            return self.binary_path
        
        # shutil.which finds executables in PATH
        # https://stackoverflow.com/questions/377017
        semgrep_path = shutil.which("semgrep")
        if semgrep_path:
            return semgrep_path
        
        raise FileNotFoundError(
            "Semgrep binary not found. Please install it:\n"
            "  pip install semgrep"
        )


@dataclass
class ContextConfig:
    """Configuration for code context extraction."""
    
    lines_before: int = 5
    lines_after: int = 5
    max_file_size_bytes: int = 1_000_000
    include_line_numbers: bool = True


@dataclass
class GeminiConfig:
    """Configuration for Google Gemini API."""
    
    api_key: Optional[str] = None
    model: str = "gemini-2.0-flash"
    max_tokens: int = 4096
    temperature: float = 0.3
    timeout: int = 60
    max_retries: int = 3
    retry_delay: float = 1.0
    batch_size: int = 10
    
    def get_api_key(self) -> str:
        if self.api_key:
            return self.api_key
        
        # Check environment variable
        env_key = os.environ.get("GEMINI_API_KEY")
        if env_key:
            return env_key
        
        # TODO: maybe support a config file too?
        raise ValueError(
            "Gemini API key not found. Set GEMINI_API_KEY environment variable."
        )


@dataclass
class ReporterConfig:
    """Configuration for report generation."""
    
    include_glossary: bool = True
    include_summary: bool = True
    max_code_snippet_lines: int = 30
    output_format: str = "markdown"  # only markdown for now


@dataclass
class Config:
    """Main configuration container."""
    
    semgrep: SemgrepConfig = field(default_factory=SemgrepConfig)
    context: ContextConfig = field(default_factory=ContextConfig)
    gemini: GeminiConfig = field(default_factory=GeminiConfig)
    reporter: ReporterConfig = field(default_factory=ReporterConfig)
    
    log_level: str = "INFO"
    skip_ai_analysis: bool = False
    
    def setup_logging(self) -> None:
        # Basic logging setup - could be improved
        logging.basicConfig(
            level=getattr(logging, self.log_level.upper()),
            format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
    
    @classmethod
    def from_env(cls) -> "Config":
        """Create config from environment variables."""
        config = cls()
        
        if os.environ.get("SAST_LOG_LEVEL"):
            config.log_level = os.environ["SAST_LOG_LEVEL"]
        
        if os.environ.get("SAST_CONTEXT_LINES"):
            try:
                lines = int(os.environ["SAST_CONTEXT_LINES"])
                config.context.lines_before = lines
                config.context.lines_after = lines
            except ValueError:
                pass  # ignore invalid values
        
        if os.environ.get("SAST_GEMINI_MODEL"):
            config.gemini.model = os.environ["SAST_GEMINI_MODEL"]
        
        if os.environ.get("SAST_BATCH_SIZE"):
            try:
                config.gemini.batch_size = int(os.environ["SAST_BATCH_SIZE"])
            except ValueError:
                pass
        
        return config
