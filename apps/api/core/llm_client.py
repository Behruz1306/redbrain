"""LLM client with multi-provider fallback chain.

Priority: Gemini (free) → Groq (free) → offline heuristics.

Free tiers:
- Gemini 2.0 Flash: 15 RPM, 1M tokens/day (aistudio.google.com/apikey)
- Groq Llama 3.3 70B: 30 RPM (console.groq.com/keys)

Set GEMINI_API_KEY and/or GROQ_API_KEY environment variables.
"""
from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any

import httpx

logger = logging.getLogger(__name__)

_ROLES_DIR = Path(__file__).parent.parent.parent.parent / ".claude" / "commands"

# Built-in system prompts for roles that don't have a .md file on disk.
# These serve as high-quality fallbacks, especially for the "hacker" role
# used by the exploit and SAST agents.
_BUILTIN_ROLE_PROMPTS: dict[str, str] = {
    "hacker": (
        "You are an elite offensive security researcher with 15 years of experience in:\n"
        "- Web application penetration testing\n"
        "- Source code auditing for 0-day vulnerabilities\n"
        "- Exploit development and weaponization\n"
        "- Bug bounty hunting ($2M+ lifetime earnings)\n"
        "- Red team operations against Fortune 500 companies\n"
        "\n"
        "Your thinking process:\n"
        "1. RECONNAISSANCE: What does this code/endpoint reveal about the system?\n"
        "2. ATTACK SURFACE: What inputs can I control? What trust boundaries exist?\n"
        "3. EXPLOITATION: How can I chain findings for maximum impact?\n"
        "4. EVASION: How do I bypass WAF/filters/sanitization?\n"
        "5. PROOF: What's the minimum viable exploit that proves the vulnerability?\n"
        "\n"
        "You never give generic advice. You give specific, actionable exploit steps with real payloads.\n"
        "You think in attack chains -- one vulnerability enabling another.\n"
        "You always consider the business impact -- what data can be stolen, what operations can be disrupted."
    ),
}


class LLMClient:
    def __init__(self) -> None:
        self.gemini_key = os.getenv("GEMINI_API_KEY", "")
        self.groq_key = os.getenv("GROQ_API_KEY", "")
        self._role_cache: dict[str, str] = {}
        self._http: httpx.AsyncClient | None = None

    @property
    def available(self) -> bool:
        return bool(self.gemini_key or self.groq_key)

    @property
    def provider(self) -> str:
        if self.gemini_key:
            return "gemini-2.0-flash"
        if self.groq_key:
            return "groq/llama-3.3-70b"
        return "offline"

    async def _get_client(self) -> httpx.AsyncClient:
        if self._http is None or self._http.is_closed:
            self._http = httpx.AsyncClient(timeout=60.0)
        return self._http

    def load_role(self, role: str) -> str:
        """Load the system prompt for a given role.

        Resolution order:
        1. In-memory cache (already loaded)
        2. File on disk: .claude/commands/redbrain-{role}.md
        3. File on disk: .claude/commands/{role}.md
        4. Built-in role prompts (_BUILTIN_ROLE_PROMPTS)
        5. Generic fallback
        """
        if role in self._role_cache:
            return self._role_cache[role]

        role_file = _ROLES_DIR / f"redbrain-{role}.md"
        if role_file.exists():
            content = role_file.read_text()
            self._role_cache[role] = content
            return content

        role_file_alt = _ROLES_DIR / f"{role}.md"
        if role_file_alt.exists():
            content = role_file_alt.read_text()
            self._role_cache[role] = content
            return content

        # Check built-in role prompts before falling back to the generic default
        if role in _BUILTIN_ROLE_PROMPTS:
            content = _BUILTIN_ROLE_PROMPTS[role]
            self._role_cache[role] = content
            return content

        default = f"You are a senior {role} security specialist."
        self._role_cache[role] = default
        return default

    async def ask(
        self,
        role: str,
        user_message: str,
        max_tokens: int = 4096,
        temperature: float = 0.3,
    ) -> str:
        system_prompt = self.load_role(role)

        if self.gemini_key:
            try:
                return await self._ask_gemini(system_prompt, user_message, max_tokens, temperature)
            except Exception as e:
                logger.warning(f"Gemini failed ({e}), trying Groq fallback...")
                if self.groq_key:
                    try:
                        return await self._ask_groq(system_prompt, user_message, max_tokens, temperature)
                    except Exception as e2:
                        logger.warning(f"Groq also failed: {e2}")
                return self._offline_fallback(role, user_message)

        if self.groq_key:
            try:
                return await self._ask_groq(system_prompt, user_message, max_tokens, temperature)
            except Exception as e:
                logger.warning(f"Groq failed: {e}")
                return self._offline_fallback(role, user_message)

        return self._offline_fallback(role, user_message)

    async def ask_json(
        self,
        role: str,
        user_message: str,
        max_tokens: int = 4096,
    ) -> dict[str, Any]:
        prompt = user_message + "\n\nRespond ONLY with valid JSON. No markdown fences, no explanation, just the JSON object."
        response = await self.ask(role, prompt, max_tokens, temperature=0.1)
        return self._parse_json(response)

    async def _ask_gemini(
        self,
        system_prompt: str,
        user_message: str,
        max_tokens: int,
        temperature: float,
    ) -> str:
        client = await self._get_client()
        url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key={self.gemini_key}"

        payload = {
            "system_instruction": {"parts": [{"text": system_prompt}]},
            "contents": [{"parts": [{"text": user_message}]}],
            "generationConfig": {
                "temperature": temperature,
                "maxOutputTokens": max_tokens,
            },
        }

        resp = await client.post(url, json=payload)
        resp.raise_for_status()
        data = resp.json()

        candidates = data.get("candidates", [])
        if candidates:
            parts = candidates[0].get("content", {}).get("parts", [])
            if parts:
                return parts[0].get("text", "")
        return ""

    async def _ask_groq(
        self,
        system_prompt: str,
        user_message: str,
        max_tokens: int,
        temperature: float,
    ) -> str:
        client = await self._get_client()

        payload = {
            "model": "llama-3.3-70b-versatile",
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_message},
            ],
            "max_tokens": max_tokens,
            "temperature": temperature,
        }

        resp = await client.post(
            "https://api.groq.com/openai/v1/chat/completions",
            json=payload,
            headers={"Authorization": f"Bearer {self.groq_key}"},
        )
        resp.raise_for_status()
        data = resp.json()

        choices = data.get("choices", [])
        if choices:
            return choices[0].get("message", {}).get("content", "")
        return ""

    def _offline_fallback(self, role: str, message: str) -> str:
        return json.dumps({
            "status": "offline",
            "note": f"No AI API key configured. Using heuristic-only mode for {role}.",
        })

    def _parse_json(self, text: str) -> dict[str, Any]:
        text = text.strip()
        if text.startswith("```"):
            lines = text.split("\n")
            json_lines = []
            in_block = False
            for line in lines:
                if line.startswith("```") and not in_block:
                    in_block = True
                    continue
                if line.startswith("```") and in_block:
                    break
                if in_block:
                    json_lines.append(line)
            text = "\n".join(json_lines)

        try:
            return json.loads(text)
        except json.JSONDecodeError:
            start = text.find("{")
            end = text.rfind("}") + 1
            if start >= 0 and end > start:
                try:
                    return json.loads(text[start:end])
                except json.JSONDecodeError:
                    pass
            return {"raw": text, "parse_error": True}

    async def close(self) -> None:
        if self._http and not self._http.is_closed:
            await self._http.aclose()


llm = LLMClient()
