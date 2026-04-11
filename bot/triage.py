"""
triage.py — send a WazuhAlert to Claude for security triage.
"""

import os
import anthropic
from parser import WazuhAlert

MODEL = "claude-opus-4-6"

SYSTEM_PROMPT = """You are an expert security analyst triaging Wazuh SIEM alerts.
You receive structured alert data and produce concise, actionable triage reports.

For each alert you must assess:
1. What actually happened (plain English, no jargon)
2. Whether this is likely a true positive or false positive — and why
3. Severity in context (the Wazuh level alone isn't enough — use your knowledge)
4. Recommended immediate actions for the SOC analyst
5. MITRE ATT&CK technique if applicable (e.g. T1070.004 - Indicator Removal)

Keep your response under 400 words. Use bullet points. Be direct — analysts are busy.
Do NOT restate the raw log data verbatim. Synthesise it."""


def build_user_message(alert: WazuhAlert) -> str:
    return f"""**Wazuh Alert Triage Request**

Rule ID: {alert.rule_id}
Rule Description: {alert.rule_description}
Severity Level: {alert.rule_level} ({alert.severity})
Agent: {alert.agent_name} ({alert.agent_ip})
Manager: {alert.manager}

Full Log:
```
{alert.full_log}
```

Please triage this alert."""


async def triage_alert(alert: WazuhAlert) -> str:
    """
    Send the alert to Claude and return the triage markdown string.
    Raises on API error — caller handles retries / error messaging.
    """
    client = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])

    message = client.messages.create(
        model=MODEL,
        max_tokens=1024,
        system=SYSTEM_PROMPT,
        messages=[
            {"role": "user", "content": build_user_message(alert)}
        ],
    )

    return message.content[0].text
