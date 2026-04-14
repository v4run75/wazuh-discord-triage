"""
triage.py — synchronous LLM triage call (run via run_in_executor).

Uses OpenRouter (openrouter.ai) — access hundreds of models with one API key.
Configure via environment variables:
  OPENROUTER_API_KEY  — your OpenRouter API key (required)
  OPENROUTER_MODEL    — model slug (default: meta-llama/llama-3.1-8b-instruct:free)
"""

import os
from openai import OpenAI
from parser import WazuhAlert

BASE_URL = "https://openrouter.ai/api/v1"
MODEL    = os.environ.get("OPENROUTER_MODEL", "google/gemma-4-31b:free")
API_KEY  = os.environ["OPENROUTER_API_KEY"]

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


def triage_alert(alert: WazuhAlert) -> str:
    """Synchronous call — run via asyncio.run_in_executor to avoid blocking."""
    client = OpenAI(
        base_url=BASE_URL,
        api_key=API_KEY,
        default_headers={
            "HTTP-Referer": "https://github.com/v4run75/wazuh-discord-triage",
            "X-Title": "Wazuh Discord Triage",
        },
    )
    resp = client.chat.completions.create(
        model=MODEL,
        max_tokens=1024,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": build_prompt(alert)},
        ],
    )
    return resp.choices[0].message.content
