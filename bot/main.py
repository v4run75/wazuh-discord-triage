"""
main.py — Discord bot that triages Wazuh alerts using Claude.

Listens for messages in the configured Wazuh alerts channel.
For each Wazuh embed or plain-text alert, replies in a thread
with a Claude triage report.
"""

import os
import asyncio
import logging
import discord
from dotenv import load_dotenv

from parser import parse_embed, parse_text, WazuhAlert
from triage import triage_alert

load_dotenv()
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("wazuh-triage")

# ── Config ────────────────────────────────────────────────────────────────────

DISCORD_TOKEN    = os.environ["DISCORD_TOKEN"]
WAZUH_CHANNEL_ID = int(os.environ["WAZUH_CHANNEL_ID"])
TRIAGE_DELAY     = float(os.environ.get("TRIAGE_DELAY_SECONDS", "2"))

# ── Bot ───────────────────────────────────────────────────────────────────────

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
    """Run Claude triage in a thread executor (sync SDK) and post result."""
    await asyncio.sleep(TRIAGE_DELAY)

    # Create thread on the alert message
    thread_name = f"Triage · Rule {alert.rule_id} · {alert.agent_name}"[:100]
    try:
        thread = await message.create_thread(
            name=thread_name,
            auto_archive_duration=1440,
        )
    except discord.HTTPException as e:
        log.warning(f"Could not create thread: {e} — replying in channel")
        thread = message.channel

    async with thread.typing():
        try:
            # Run the synchronous Anthropic SDK call in a thread pool
            # so we don't block the Discord event loop
            loop = asyncio.get_event_loop()
            triage_text = await loop.run_in_executor(None, triage_alert, alert)
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

    embed = discord.Embed(
        title=f"🤖 AI Triage · Rule {alert.rule_id}",
        description=triage_text,
        color=severity_color(alert.rule_level),
    )
    embed.add_field(name="Agent",  value=f"`{alert.agent_name}` ({alert.agent_ip})", inline=True)
    embed.add_field(name="Level",  value=f"`{alert.rule_level}` {alert.severity}",   inline=True)
    embed.add_field(name="Rule",   value=alert.rule_description or "—",              inline=False)
    embed.set_footer(text=f"Triaged by Claude · Manager: {alert.manager}")

    await thread.send(embed=embed)
    log.info(f"Triage posted: rule={alert.rule_id} agent={alert.agent_name}")


# ── Events ────────────────────────────────────────────────────────────────────

@bot.event
async def on_ready():
    log.info(f"Logged in as {bot.user} (id={bot.user.id})")
    log.info(f"Watching channel id={WAZUH_CHANNEL_ID}")


@bot.event
async def on_message(message: discord.Message):
    if message.channel.id != WAZUH_CHANNEL_ID:
        return
    if message.author == bot.user:
        return

    log.debug(
        f"Message in wazuh channel: author={message.author} "
        f"embeds={len(message.embeds)} content_len={len(message.content)}"
    )

    alert = None

    # Try embed format first (standard Wazuh Discord integration)
    for embed in message.embeds:
        alert = parse_embed(embed)
        if alert:
            break

    # Fall back to plain text parsing (some Wazuh webhook configs post text)
    if not alert and message.content:
        alert = parse_text(message.content)

    if alert:
        log.info(
            f"Wazuh alert: rule={alert.rule_id} level={alert.rule_level} "
            f"agent={alert.agent_name} desc={alert.rule_description!r}"
        )
        asyncio.create_task(post_triage(message, alert))
    else:
        log.debug("Message in wazuh channel did not match Wazuh alert format — skipped")


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    bot.run(DISCORD_TOKEN, log_handler=None)
