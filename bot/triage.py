"""
triage.py — synchronous LLM triage call (run via run_in_executor).

Uses OpenRouter (openrouter.ai) — access hundreds of models with one API key.
Configure via environment variables:
  OPENROUTER_API_KEY  — your OpenRouter API key (required)
  OPENROUTER_MODEL    — model slug (default: google/gemini-2.5-flash)

Free models share upstream quota across all OpenRouter users. If the primary
model is rate-limited, the bot automatically falls back through FALLBACK_MODELS.
"""

import os
import time
from openai import OpenAI, RateLimitError
from parser import WazuhAlert
from history import get_previous_alerts

BASE_URL = "https://openrouter.ai/api/v1"
MODEL    = os.environ.get("OPENROUTER_MODEL", "google/gemini-2.5-flash")
API_KEY  = os.environ["OPENROUTER_API_KEY"]

# Fallback chain — tried in order on 429 (cheapest paid first, Sonnet last resort)
FALLBACK_MODELS = [
    "google/gemma-4-31b-it",
    "anthropic/claude-sonnet-4-5",
    "openai/gpt-oss-120b:free",
    "nvidia/nemotron-3-super-120b-a12b:free",
    "qwen/qwen3-next-80b-a3b-instruct:free",
    "meta-llama/llama-3.2-3b-instruct:free",
    "openrouter/free",
]

SYSTEM_PROMPT = """You are a security analyst triaging Wazuh SIEM alerts.

For each alert provide:
1. What happened (plain English)
2. True positive or false positive — and why
3. Severity in context

Keep response under 150 words. Be direct. Do not restate raw log data."""


def build_prompt(alert: WazuhAlert) -> str:
    previous = get_previous_alerts(alert, limit=2)

    history_section = ""
    if previous:
        history_section = "\n\n**Previous alerts (same rule + agent) for comparison:**\n"
        for i, row in enumerate(previous, 1):
            label = "Previous" if i == 1 else f"{i} alerts ago"
            history_section += f"\n--- {label} ({row['received_at']} UTC) ---\n```\n{row['full_log']}\n```"
        history_section += "\n\nNote any changes between previous and current logs (e.g. ports opened/closed, new processes)."

    return f"""**Wazuh Alert Triage Request**

Rule ID: {alert.rule_id}
Description: {alert.rule_description}
Severity: Level {alert.rule_level} ({alert.severity})
Agent: {alert.agent_name} ({alert.agent_ip})
Manager: {alert.manager}

**Current Log:**
```
{alert.full_log}
```
{history_section}
Triage this alert."""


def _call(client: OpenAI, model: str, prompt: str) -> str:
    resp = client.chat.completions.create(
        model=model,
        max_tokens=1024,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ],
    )
    return resp.choices[0].message.content


def triage_alert(alert: WazuhAlert, extra_context: str = "") -> str:
    """Synchronous call — run via asyncio.run_in_executor to avoid blocking.
    Retries once on 429, then falls back through FALLBACK_MODELS."""
    client = OpenAI(
        base_url=BASE_URL,
        api_key=API_KEY,
        default_headers={
            "HTTP-Referer": "https://github.com/v4run75/wazuh-discord-triage",
            "X-Title": "Wazuh Discord Triage",
        },
    )
    prompt = build_prompt(alert)
    if extra_context:
        prompt += f"\n\nAdditional context from analyst:\n{extra_context}"
    models_to_try = [MODEL] + FALLBACK_MODELS

    for i, model in enumerate(models_to_try):
        try:
            # Retry the same model once after a short wait before falling back
            try:
                return _call(client, model, prompt)
            except RateLimitError:
                time.sleep(5)
                return _call(client, model, prompt)
        except RateLimitError:
            if i < len(models_to_try) - 1:
                continue  # try next model
            raise
