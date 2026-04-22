"""
LLM client for Google Gemini API.

Handles initialization and raw content generation.
All API key and model configuration comes from config.settings.
"""

from __future__ import annotations

import json
from typing import Optional

from security_system.config.settings import settings
from security_system.utils.logger import get_logger

logger = get_logger(__name__)

try:
    from google import genai
    from google.genai import types as genai_types
except ImportError as exc:
    raise ImportError(
        "google-genai is required. Install it with: pip install google-genai"
    ) from exc


class LLMClient:
    """
    Thin wrapper around the Google Gemini API client.

    Responsibilities:
    - Initialize the API client using the configured API key.
    - Send a prompt and return the raw text response.
    - Handle API-level errors cleanly.

    Usage:
        client = LLMClient()
        text = client.generate(system_prompt, user_prompt)
    """

    def __init__(self) -> None:
        if not settings.is_llm_configured():
            raise EnvironmentError(
                "GOOGLE_API_KEY is not set. "
                "Export it or add it to security_system/.env"
            )
        self._client = genai.Client(api_key=settings.google_api_key)
        self._model = settings.llm_model
        logger.info("LLMClient initialized (model: %s)", self._model)

    def generate(self, system_prompt: str, user_prompt: str) -> Optional[str]:
        """
        Sends both prompts to Gemini and returns the response text.

        Args:
            system_prompt: Role/instruction context for the model.
            user_prompt:   The specific request or data to analyze.

        Returns:
            Raw response text, or None on failure.
        """
        try:
            response = self._client.models.generate_content(
                model=self._model,
                contents=[
                    {"role": "user", "parts": [{"text": system_prompt}]},
                    {"role": "user", "parts": [{"text": user_prompt}]},
                ],
                config=genai_types.GenerateContentConfig(
                    temperature=0.3,
                    max_output_tokens=settings.llm_max_tokens,
                ),
            )

            text = response.text
            if not text:
                logger.error("Gemini returned an empty response")
                return None

            logger.debug("Received LLM response (%d chars)", len(text))
            return text

        except Exception as exc:  # pylint: disable=broad-except
            logger.error("Gemini API call failed: %s", exc)
            return None

    def generate_json(self, system_prompt: str, user_prompt: str) -> Optional[dict]:
        """
        Calls generate() and parses the response as JSON.

        Returns:
            Parsed dict, or None if the response is empty or not valid JSON.
        """
        text = self.generate(system_prompt, user_prompt)
        if text is None:
            return None

        # Strip markdown code fences if the model wraps its output
        clean = text.strip()
        if clean.startswith("```"):
            clean = clean.split("\n", 1)[-1]
            clean = clean.rsplit("```", 1)[0].strip()

        try:
            return json.loads(clean)
        except json.JSONDecodeError as exc:
            logger.error("Failed to parse LLM response as JSON: %s", exc)
            return None
