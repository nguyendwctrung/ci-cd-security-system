"""
Environment-based configuration for the CI/CD Security System.

Loads values from environment variables or .env file.
Provides a single `settings` singleton for access across modules.
"""

import os
import logging
from dataclasses import dataclass, field
from pathlib import Path

from .constants import REPORTS_DIR, LLM_MODEL, LLM_MAX_TOKENS, LLM_TIMEOUT

# Load .env file if present (optional dependency)
try:
    from dotenv import load_dotenv
    _env_path = Path("security_system/.env")
    if _env_path.exists():
        load_dotenv(_env_path)
except ImportError:
    pass  # python-dotenv not installed; rely on shell environment


@dataclass
class Settings:
    """
    Runtime settings resolved from environment variables.

    Access via the module-level `settings` singleton:
        from security_system.config.settings import settings
    """

    # LLM
    google_api_key: str = field(default_factory=lambda: os.getenv("GOOGLE_API_KEY", ""))
    llm_model: str = field(default_factory=lambda: os.getenv("LLM_MODEL", LLM_MODEL))
    llm_max_tokens: int = field(default_factory=lambda: int(os.getenv("LLM_MAX_TOKENS", LLM_MAX_TOKENS)))
    llm_timeout: int = field(default_factory=lambda: int(os.getenv("LLM_TIMEOUT", LLM_TIMEOUT)))

    # Logging
    log_level: str = field(default_factory=lambda: os.getenv("LOG_LEVEL", "INFO").upper())

    # Reports
    reports_dir: Path = field(default_factory=lambda: Path(os.getenv("REPORTS_DIR", str(REPORTS_DIR))))

    # CI/CD context
    github_sha: str = field(default_factory=lambda: os.getenv("GITHUB_SHA", ""))
    github_ref: str = field(default_factory=lambda: os.getenv("GITHUB_REF", ""))
    ci_environment: bool = field(default_factory=lambda: os.getenv("CI", "false").lower() == "true")

    def is_llm_configured(self) -> bool:
        """Returns True if the LLM API key is set."""
        return bool(self.google_api_key)

    def get_log_level(self) -> int:
        """Returns the numeric log level."""
        return getattr(logging, self.log_level, logging.INFO)

    def ensure_reports_dir(self) -> None:
        """Creates the reports directory if it does not exist."""
        self.reports_dir.mkdir(parents=True, exist_ok=True)


# Module-level singleton — import and use directly
settings = Settings()
