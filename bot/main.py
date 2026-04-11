"""
main.py — Discord bot that triages Wazuh alerts using Claude.

Listens for messages in the configured Wazuh alerts channel.
For each Wazuh embed, replies in a thread with a Claude triage report.
"""

import os
import asyncio
import logging
import discord
from discord.ext import commands
from dotenv import load_dotenv

from parser import parse_embed, WazuhAlert
from triage import triage_alert

load_dotenv()
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("wazuh-triage")

# ── Config ────────────────────────────────────────────────────────────────────

DISCORD_TOKEN      = os.environ["DISCORD_TOKEN"]
WAZUH_CHANNEL_ID   = int(os.environ["WAZUH_CHANNEL_ID"])   # channel Wazuh posts to
TRIAGE_BOT_NAME    = os.environ.get("TRIAGE_BOT_NAME", "Wazuh Triage Bot")

# How long to wait between receiving an alert and posting triage (seconds).
# Small delay avoids race conditions if Wazuh edits the embed after posting.
TRIAGE_DELAY       = float(os.environ.get("TRIAGE_DELAY_SECONDS", "2"))

# ── Bot setup ─────────────────────────────────────────────────────────────────

intents = discord.Intents.default()
intents.message_content = True
intents.messages = True

bot = discord.Client(intents=intents)


def severity_color(level: int) -> discord.Color:
    if level >= 12: return discord.Color.dark_red()
    if level >= 9:  return discord.Color.orange()
    if level >= 6:  return discord.Color.yellow()
    if level >= 3:  return discord.Color.blue()
    return discord.Color.greyple()


async def post_triage(message: discord.Message, alert: WazuhAlert):
    """Run Claude triage and post the result as a thread reply."""
    await asyncio.sleep(TRIAGE_DELAY)

    # Create or fetch thread on the alert message
    try:
        thread = await message.create_thread(
            name=f"Triage · Rule {alert.rule_id} · {alert.agent_name}",
            auto_archive_duration=1440,  # 24h
        )
    except discord.HTTPException:
        # Thread already exists or can't be created — fall back to channel reply
        thread = message.channel

    # Typing indicator while Claude thinks
    async with thread.typing():
        try:
            triage_text = await triage_alert(alert)
        except Exception as e:
            log.error(f"Triage API error for rule {alert.rule_id}: {e}")
            await thread.send(
                embed=discord.Embed(
                    title="⚠️ Triage Failed",
                    description=f"Claude API error: `{e}`\nPlease triage manually.",
                    color=discord.Color.red(),
                )
            )
            return

    # Build the triage embed
    embed = discord.Embed(
        title=f"🤖 AI Triage · Rule {alert.rule_id}",
        description=triage_text,
        color=severity_color(alert.rule_level),
    )
    embed.add_field(name="Agent",    value=f"`{alert.agent_name}` ({alert.agent_ip})", inline=True)
    embed.add_field(name="Level",    value=f"`{alert.rule_level}` {alert.severity}",   inline=True)
    embed.add_field(name="Rule",     value=alert.rule_description,                     inline=False)
    embed.set_footer(text=f"Triaged by Claude · Manager: {alert.manager}")

    await thread.send(embed=embed)
    log.info(f"Posted triage for rule {alert.rule_id} on agent {alert.agent_name}")


# ── Event handlers ────────────────────────────────────────────────────────────

@bot.event
async def on_ready():
    log.info(f"Logged in as {bot.user} (id={bot.user.id})")
    log.info(f"Watching channel id={WAZUH_CHANNEL_ID} for Wazuh alerts")


@bot.event
async def on_message(message: discord.Message):
    # Only care about the configured Wazuh channel
    if message.channel.id != WAZUH_CHANNEL_ID:
        return

    # Ignore messages from ourselves
    if message.author == bot.user:
        return

    # Wazuh posts embeds — skip plain text messages
    if not message.embeds:
        return

    for embed in message.embeds:
        alert = parse_embed(embed)
        if alert:
            log.info(
                f"Wazuh alert detected: rule={alert.rule_id} "
                f"level={alert.rule_level} agent={alert.agent_name}"
            )
            # Fire and forget — don't block the event loop
            asyncio.create_task(post_triage(message, alert))


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    bot.run(DISCORD_TOKEN, log_handler=None)
