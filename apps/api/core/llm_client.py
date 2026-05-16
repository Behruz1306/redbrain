from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import anthropic


_ROLES_DIR = Path(__file__).parent.parent.parent.parent / ".claude" / "commands"


class LLMClient:
    """Claude API wrapper that loads system prompts from GStack role files."""

    def __init__(self) -> None:
        self.api_key = os.getenv("ANTHROPIC_API_KEY", "")
        self.model = "claude-sonnet-4-6-20250514"
        self._client: anthropic.AsyncAnthropic | None = None
        self._role_cache: dict[str, str] = {}

    @property
    def client(self) -> anthropic.AsyncAnthropic:
        if self._client is None:
            self._client = anthropic.AsyncAnthropic(api_key=self.api_key)
        return self._client

    def load_role(self, role_name: str) -> str:
        """Load a GStack role markdown file as system prompt."""
        if role_name in self._role_cache:
            return self._role_cache[role_name]

        role_file = _ROLES_DIR / f"{role_name}.md"
        if role_file.exists():
            content = role_file.read_text()
            self._role_cache[role_name] = content
            return content

        return f"You are a {role_name} agent."

    async def ask(
        self,
        role: str,
        user_message: str,
        max_tokens: int = 4096,
        temperature: float = 0.3,
    ) -> str:
        """Send a message to Claude with a role-based system prompt."""
        if not self.api_key:
            return self._offline_fallback(role, user_message)

        system_prompt = self.load_role(role)
        response = await self.client.messages.create(
            model=self.model,
            max_tokens=max_tokens,
            temperature=temperature,
            system=system_prompt,
            messages=[{"role": "user", "content": user_message}],
        )
        return response.content[0].text

    async def ask_json(
        self,
        role: str,
        user_message: str,
        max_tokens: int = 4096,
    ) -> dict[str, Any]:
        """Ask Claude and parse JSON response."""
        import json

        response_text = await self.ask(role, user_message, max_tokens)
        # Try to extract JSON from response
        try:
            # Look for JSON block in markdown
            if "```json" in response_text:
                start = response_text.index("```json") + 7
                end = response_text.index("```", start)
                return json.loads(response_text[start:end])
            elif "```" in response_text:
                start = response_text.index("```") + 3
                end = response_text.index("```", start)
                return json.loads(response_text[start:end])
            else:
                return json.loads(response_text)
        except (json.JSONDecodeError, ValueError):
            return {"raw_response": response_text}

    def _offline_fallback(self, role: str, message: str) -> str:
        """Return a placeholder when API key is not available."""
        return f"[{role}] Analysis pending — ANTHROPIC_API_KEY not configured."


llm = LLMClient()
