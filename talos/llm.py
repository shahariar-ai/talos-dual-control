"""LLM access through Nebius Token Factory (OpenAI-compatible API)."""
from __future__ import annotations

import json
import os
import re
from typing import Protocol

# Base URL from the Nebius Token Factory API reference.
NEBIUS_BASE_URL = "https://api.tokenfactory.nebius.com/v1/"

# Model IDs are taken from public Token Factory listings. Confirm the exact
# strings in your Token Factory model catalogue and override with env vars if
# they differ: TALOS_MAKER_MODEL / TALOS_CHECKER_MODEL.
DEFAULT_MAKER_MODEL = "nvidia/nemotron-3-super-120b-a12b"  # Nemotron 3 Super: fast everyday calls
DEFAULT_CHECKER_MODEL = "nvidia/Nemotron-3-Ultra-550b-a55b"  # Nemotron 3 Ultra: serious reasoning


class LLM(Protocol):
    name: str

    def chat(self, messages: list[dict], *, temperature: float = 0.2, max_tokens: int = 1024) -> str: ...


class NebiusLLM:
    """Thin wrapper that also meters calls and tokens per model."""

    def __init__(self, model: str, api_key: str | None = None, base_url: str | None = None, timeout: float = 90.0):
        from openai import OpenAI  # imported lazily so offline mode needs no key

        key = api_key or os.environ.get("NEBIUS_API_KEY")
        if not key:
            raise RuntimeError("NEBIUS_API_KEY is not set")
        self.name = model
        self.client = OpenAI(
            base_url=base_url or os.environ.get("NEBIUS_BASE_URL", NEBIUS_BASE_URL),
            api_key=key, timeout=timeout, max_retries=2,
        )
        self.calls = 0
        self.prompt_tokens = 0
        self.completion_tokens = 0

    def chat(self, messages: list[dict], *, temperature: float = 0.2, max_tokens: int = 1024) -> str:
        resp = self.client.chat.completions.create(
            model=self.name, messages=messages, temperature=temperature, max_tokens=max_tokens
        )
        self.calls += 1
        u = getattr(resp, "usage", None)
        if u:
            self.prompt_tokens += getattr(u, "prompt_tokens", 0) or 0
            self.completion_tokens += getattr(u, "completion_tokens", 0) or 0
        return resp.choices[0].message.content or ""

    @property
    def usage(self) -> dict:
        return {"model": self.name, "calls": self.calls,
                "prompt_tokens": self.prompt_tokens, "completion_tokens": self.completion_tokens}


_THINK = re.compile(r"<think>.*?</think>", re.S)


def extract_json(text: str) -> dict | None:
    """Pull the first JSON object out of a model reply (tolerates prose and <think> blocks)."""
    text = _THINK.sub("", text or "")
    start = text.find("{")
    while start != -1:
        depth, in_str, esc = 0, False, False
        for i in range(start, len(text)):
            c = text[i]
            if in_str:
                if esc:
                    esc = False
                elif c == "\\":
                    esc = True
                elif c == '"':
                    in_str = False
                continue
            if c == '"':
                in_str = True
            elif c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    try:
                        obj = json.loads(text[start:i + 1])
                        if isinstance(obj, dict):
                            return obj
                    except json.JSONDecodeError:
                        break
                    break
        start = text.find("{", start + 1)
    return None
