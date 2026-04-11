"""
parser.py — extract structured data from Wazuh Discord embeds.

Wazuh posts embeds with this layout (confirmed from live alerts):
  Title:       "Wazuh Alert - Rule 550"
  Description: "Integrity checksum changed."
  Fields:      Agent | Level | Full Log
  Footer:      "Wazuh Manager: Wazuh-Server"
"""

import re
from dataclasses import dataclass, field


@dataclass
class WazuhAlert:
    rule_id: str = ""
    rule_description: str = ""
    rule_level: int = 0
    agent_name: str = ""
    agent_ip: str = ""
    manager: str = ""
    full_log: str = ""

    @property
    def severity(self) -> str:
        if self.rule_level >= 12:
            return "🔴 CRITICAL"
        elif self.rule_level >= 9:
            return "🟠 HIGH"
        elif self.rule_level >= 6:
            return "🟡 MEDIUM"
        elif self.rule_level >= 3:
            return "🔵 LOW"
        return "⚪ INFO"


def parse_embed(embed) -> WazuhAlert | None:
    """
    Parse a discord.Embed object into a WazuhAlert.
    Returns None if the embed is not a Wazuh alert.
    """
    title = embed.title or ""

    # Must match "Wazuh Alert - Rule NNN"
    rule_match = re.match(r"Wazuh Alert\s*-\s*Rule\s*(\d+)", title, re.IGNORECASE)
    if not rule_match:
        return None

    alert = WazuhAlert()
    alert.rule_id = rule_match.group(1)
    alert.rule_description = embed.description or ""

    # Footer: "Wazuh Manager: Wazuh-Server"
    if embed.footer and embed.footer.text:
        m = re.search(r"Wazuh Manager:\s*(.+)", embed.footer.text)
        if m:
            alert.manager = m.group(1).strip()

    # Fields: Agent, Level, Full Log
    for field in embed.fields:
        name = (field.name or "").strip().lower()
        value = (field.value or "").strip()

        if name == "agent":
            # "Blood-G14 (192.168.1.98)"
            ip_match = re.search(r"\(([^)]+)\)", value)
            if ip_match:
                alert.agent_ip = ip_match.group(1)
                alert.agent_name = value[: value.index("(")].strip()
            else:
                alert.agent_name = value

        elif name == "level":
            try:
                alert.rule_level = int(value)
            except ValueError:
                pass

        elif name == "full log":
            alert.full_log = value

    return alert
