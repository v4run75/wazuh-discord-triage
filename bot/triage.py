"""
triage.py — synchronous LLM triage call (run via run_in_executor).

Supports local Ollama or any OpenAI-compatible API.
Configure via environment variables:
  OLLAMA_BASE_URL  — Ollama endpoint (default: http://localhost:11434/v1)
  OLLAMA_MODEL     — model name (default: phi3:mini)
"""

import os
from openai import OpenAI
from parser import WazuhAlert

BASE_URL = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434/v1")
MODEL    = os.environ.get("OLLAMA_MODEL", "phi3:mini")
API_KEY  = os.environ.get("OPENAI_API_KEY", "ollama")  # Ollama ignores this

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
    client = OpenAI(base_url=BASE_URL, api_key=API_KEY)
    resp = client.chat.completions.create(
        model=MODEL,
        max_tokens=1024,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": build_prompt(alert)},
        ],
    )
    return resp.choices[0].message.content
