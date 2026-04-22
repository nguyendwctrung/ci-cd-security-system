"""
LLM client for Google Gemini API (google-genai SDK).

Handles initialization and content generation via Gemini.
All API key and model configuration comes from config.settings.
"""

from __future__ import annotations

import json
import os
from typing import Optional

from security_system.utils.logger import get_logger

logger = get_logger(__name__)

try:
    from google import genai
except ImportError as exc:
    raise ImportError(
        "google-genai is required. Install with: pip install google-genai"
    ) from exc


class LLMClient:
    """
    Thin wrapper around the Google Gemini API client.

    Responsibilities:
    - Initialize the API client using GOOGLE_API_KEY env var
    - Send prompts and return raw text or parsed JSON responses
    - Handle API-level errors gracefully without crashing

    Usage:
        client = LLMClient()
        text = client.generate(system_prompt, user_prompt)
        result = client.generate_json(system_prompt, user_prompt)
    """

    def __init__(self, api_key: Optional[str] = None) -> None:
        """Initialize Gemini client with API key from env or parameter."""
        key = api_key or os.getenv("GOOGLE_API_KEY", "").strip()
        
        if not key:
            raise EnvironmentError(
                "GOOGLE_API_KEY not set. "
                "Export GOOGLE_API_KEY or pass api_key parameter."
            )
        
        self._client = genai.Client(api_key=key)
        self._model = "gemini-2.5-flash-lite"
        logger.info("LLMClient initialized (model: %s)", self._model)

    def generate(self, system_prompt: str, user_prompt: str) -> Optional[str]:
        """
        Send prompts to Gemini and return raw text response.

        Args:
            system_prompt: System instructions
            user_prompt:   Analysis request

        Returns:
            Raw response text, or None on API failure
        """
        try:
            full_prompt = f"{system_prompt}\n\n{user_prompt}"
            response = self._client.models.generate_content(
                model=self._model,
                contents=full_prompt,
            )

            if not response.text:
                logger.error("Gemini returned empty response")
                return None

            logger.debug("Received Gemini response (%d chars)", len(response.text))
            return response.text

        except Exception as exc:  # pylint: disable=broad-except
            logger.error("Gemini API call failed: %s", exc)
            return None

    def generate_json(
        self,
        system_prompt: str,
        user_prompt: str,
    ) -> Optional[dict]:
        """
        Send prompts to Gemini and parse response as JSON.

        Args:
            system_prompt: System instructions defining the model's role
            user_prompt:   The actual security analysis request

        Returns:
            Parsed JSON dict, or None on failure
        """
        text = self.generate(system_prompt, user_prompt)
        if text is None:
            return None

        # Parse response as JSON
        json_text = text.strip()
        
        # Strip markdown code fences if present
        if json_text.startswith("```"):
            json_text = json_text.split("\n", 1)[-1]
            json_text = json_text.rsplit("```", 1)[0].strip()

        try:
            result = json.loads(json_text)
            logger.info("Gemini response parsed successfully")
            return result
        except json.JSONDecodeError as exc:
            logger.error("Failed to parse Gemini response as JSON: %s", exc)
            return None
