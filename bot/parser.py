"""
parser.py — extract structured data from Wazuh Discord messages.

Handles two formats:
  1. Discord embed  (standard Wazuh Discord integration)
  2. Plain text     (some webhook configs post raw text)

Confirmed embed layout from live alerts:
  Title:       "Wazuh Alert - Rule 550"
  Description: "Integrity checksum changed."
  Fields:      Agent | Level | Full Log
  Footer:      "Wazuh Manager: Wazuh-Server"
"""

import re
from dataclasses import dataclass


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
        if self.rule_level >= 12: return "🔴 CRITICAL"
        if self.rule_level >= 9:  return "🟠 HIGH"
        if self.rule_level >= 6:  return "🟡 MEDIUM"
        if self.rule_level >= 3:  return "🔵 LOW"
        return "⚪ INFO"


def parse_embed(embed) -> WazuhAlert | None:
    """Parse a discord.Embed into a WazuhAlert. Returns None if not a Wazuh alert."""
    title = embed.title or ""

    rule_match = re.match(r"Wazuh Alert\s*[-–]\s*Rule\s*(\d+)", title, re.IGNORECASE)
    if not rule_match:
        return None

    alert = WazuhAlert()
    alert.rule_id = rule_match.group(1)
    alert.rule_description = (embed.description or "").strip()

    if embed.footer and embed.footer.text:
        m = re.search(r"Wazuh Manager:\s*(.+)", embed.footer.text)
        if m:
            alert.manager = m.group(1).strip()

    for f in embed.fields:
        name  = (f.name  or "").strip().lower()
        value = (f.value or "").strip()

        if name == "agent":
            ip_match = re.search(r"\(([^)]+)\)", value)
            if ip_match:
                alert.agent_ip   = ip_match.group(1)
                alert.agent_name = value[:value.index("(")].strip()
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


def parse_text(content: str) -> WazuhAlert | None:
    """
    Parse a plain-text Wazuh alert message.

    Expected format (line-based):
        Wazuh Alert - Rule 533
        <rule description>
        Agent
        <agent name> (<ip>)
        Level
        <level number>
        Full Log
        <log lines...>
        Wazuh Manager: <manager>
    """
    # Must contain the Wazuh Alert header
    rule_match = re.search(r"Wazuh Alert\s*[-–]\s*Rule\s*(\d+)", content, re.IGNORECASE)
    if not rule_match:
        return None

    alert = WazuhAlert()
    alert.rule_id = rule_match.group(1)
    lines = content.splitlines()

    i = 0
    while i < len(lines):
        line = lines[i].strip()

        if re.match(r"Wazuh Alert\s*[-–]\s*Rule\s*\d+", line, re.IGNORECASE):
            # Description is the next non-empty line
            j = i + 1
            while j < len(lines) and not lines[j].strip():
                j += 1
            if j < len(lines):
                next_line = lines[j].strip()
                # Only grab it if it's not a field header
                if next_line.lower() not in ("agent", "level", "full log"):
                    alert.rule_description = next_line

        elif line.lower() == "agent" and i + 1 < len(lines):
            agent_val = lines[i + 1].strip()
            ip_match = re.search(r"\(([^)]+)\)", agent_val)
            if ip_match:
                alert.agent_ip   = ip_match.group(1)
                alert.agent_name = agent_val[:agent_val.index("(")].strip()
            else:
                alert.agent_name = agent_val
            i += 1

        elif line.lower() == "level" and i + 1 < len(lines):
            try:
                alert.rule_level = int(lines[i + 1].strip())
            except ValueError:
                pass
            i += 1

        elif line.lower() == "full log":
            # Collect everything until "Wazuh Manager:" line
            log_lines = []
            j = i + 1
            while j < len(lines):
                if re.match(r"Wazuh Manager:", lines[j], re.IGNORECASE):
                    break
                log_lines.append(lines[j])
                j += 1
            alert.full_log = "\n".join(log_lines).strip()
            i = j - 1

        elif re.match(r"Wazuh Manager:\s*(.+)", line, re.IGNORECASE):
            m = re.match(r"Wazuh Manager:\s*(.+)", line, re.IGNORECASE)
            alert.manager = m.group(1).strip()

        i += 1

    return alert
