"""
triage.py — synchronous LLM triage call (run via run_in_executor).

Uses OpenRouter (openrouter.ai) — access hundreds of models with one API key.
Configure via environment variables:
  OPENROUTER_API_KEY  — your OpenRouter API key (required)
  OPENROUTER_MODEL    — model slug (default: google/gemma-4-31b-it:free)

Free models share upstream quota across all OpenRouter users. If the primary
model is rate-limited, the bot automatically falls back through FALLBACK_MODELS.
"""

import os
import time
from openai import OpenAI, RateLimitError
from parser import WazuhAlert

BASE_URL = "https://openrouter.ai/api/v1"
MODEL    = os.environ.get("OPENROUTER_MODEL", "google/gemma-4-31b-it:free")
API_KEY  = os.environ["OPENROUTER_API_KEY"]

# Fallback chain — tried in order on 429
FALLBACK_MODELS = [
    "openai/gpt-oss-120b:free",           # 120B dense, best reasoning
    "nvidia/nemotron-3-super-120b-a12b:free",  # 120B MoE (12B active)
    "qwen/qwen3-next-80b-a3b-instruct:free",   # 80B MoE (3B active)
]

SYSTEM_PROMPT = """You are an expert security analyst triaging Wazuh SIEM alerts.
You receive structured alert data and produce concise, actionable triage reports.

For each alert assess:
1. What actually happened (plain English, no jargon)
2. True positive or false positive — and why
3. Severity in context (Wazuh level alone isn't enough — use your knowledge)
4. Recommended immediate actions for the SOC analyst
5. MITRE ATT&CK technique if applicable (e.g. T1070.004)

Keep response under 400 words. Use bullet points. Be direct.
Do NOT restate raw log data verbatim — synthesise it."""


def build_prompt(alert: WazuhAlert) -> str:
    return f"""**Wazuh Alert Triage Request**

Rule ID: {alert.rule_id}
Description: {alert.rule_description}
Severity: Level {alert.rule_level} ({alert.severity})
Agent: {alert.agent_name} ({alert.agent_ip})
Manager: {alert.manager}

Full Log:
```
{alert.full_log}
```

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


def triage_alert(alert: WazuhAlert) -> str:
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
