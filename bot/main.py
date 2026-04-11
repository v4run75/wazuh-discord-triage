"""
main.py — Discord bot that triages Wazuh alerts using Claude.
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
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("wazuh-triage")

# Reduce noise from discord.py internals but keep our own DEBUG
logging.getLogger("discord.gateway").setLevel(logging.WARNING)
logging.getLogger("discord.http").setLevel(logging.WARNING)
logging.getLogger("discord.client").setLevel(logging.INFO)

DISCORD_TOKEN    = os.environ["DISCORD_TOKEN"]
WAZUH_CHANNEL_ID = int(os.environ["WAZUH_CHANNEL_ID"])
TRIAGE_DELAY     = float(os.environ.get("TRIAGE_DELAY_SECONDS", "2"))

intents = discord.Intents.default()
intents.message_content = True
intents.messages = True

bot = discord.Client(intents=intents)

# Track messages we've already triaged (avoid double-processing from edit events)
_triaged: set[int] = set()


def severity_color(level: int) -> discord.Color:
    if level >= 12: return discord.Color.dark_red()
    if level >= 9:  return discord.Color.orange()
    if level >= 6:  return discord.Color.yellow()
    if level >= 3:  return discord.Color.blue()
    return discord.Color.greyple()


async def process_message(message: discord.Message):
    """Attempt to parse and triage a message from the Wazuh channel."""
    if message.author == bot.user:
        return

    # Log everything we receive so we can diagnose format issues
    log.info(
        f"[RAW] author={message.author!r} webhook_id={message.webhook_id} "
        f"embeds={len(message.embeds)} content={message.content[:80]!r}"
    )
    for i, embed in enumerate(message.embeds):
        log.info(
            f"  embed[{i}] title={embed.title!r} desc={str(embed.description)[:60]!r} "
            f"author={embed.author.name if embed.author else None!r} "
            f"footer={embed.footer.text if embed.footer else None!r} "
            f"fields={[f.name for f in embed.fields]}"
        )

    alert = None

    # Try embed format first
    for embed in message.embeds:
        alert = parse_embed(embed)
        if alert:
            log.info(f"Parsed via embed: rule={alert.rule_id} level={alert.rule_level} agent={alert.agent_name}")
            break

    # Fall back to plain text
    if not alert and message.content:
        alert = parse_text(message.content)
        if alert:
            log.info(f"Parsed via text: rule={alert.rule_id} level={alert.rule_level} agent={alert.agent_name}")

    if not alert:
        log.info("Message did not match Wazuh alert format — skipped")
        return

    _triaged.add(message.id)
    asyncio.create_task(post_triage(message, alert))


async def post_triage(message: discord.Message, alert: WazuhAlert):
    await asyncio.sleep(TRIAGE_DELAY)

    thread_name = f"Triage · Rule {alert.rule_id} · {alert.agent_name}"[:100]
    try:
        thread = await message.create_thread(
            name=thread_name,
            auto_archive_duration=1440,
        )
    except discord.HTTPException as e:
        log.warning(f"Could not create thread ({e}) — replying in channel")
        thread = message.channel

    async with thread.typing():
        try:
            loop = asyncio.get_event_loop()
            triage_text = await loop.run_in_executor(None, triage_alert, alert)
        except Exception as e:
            log.error(f"Triage API error: {e}")
            await thread.send(
                embed=discord.Embed(
                    title="⚠️ Triage Failed",
                    description=f"`{e}`\nPlease triage manually.",
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


@bot.event
async def on_ready():
    log.info(f"Logged in as {bot.user} (id={bot.user.id})")
    log.info(f"Watching channel id={WAZUH_CHANNEL_ID}")
    log.info(f"Guilds: {[f'{g.name} (id={g.id})' for g in bot.guilds]}")
    # Verify the bot can actually see the channel
    channel = bot.get_channel(WAZUH_CHANNEL_ID)
    if channel:
        log.info(f"Channel found: #{channel.name} in {channel.guild.name}")
        perms = channel.permissions_for(channel.guild.me)
        log.info(f"Permissions: send={perms.send_messages} read={perms.read_messages} "
                 f"read_history={perms.read_message_history} threads={perms.create_public_threads}")
    else:
        log.error(
            f"Channel {WAZUH_CHANNEL_ID} NOT FOUND — bot may lack access. "
            "Check bot permissions and that it's in the right server."
        )
        log.error(f"All visible channels: {[(c.name, c.id) for g in bot.guilds for c in g.channels]}")


@bot.event
async def on_message(message: discord.Message):
    # Log EVERY message before filtering — critical for debugging
    log.info(f"[on_message] channel={message.channel.id} author={message.author} "
             f"webhook_id={message.webhook_id} embeds={len(message.embeds)}")

    if message.channel.id != WAZUH_CHANNEL_ID:
        return
    if message.id in _triaged:
        return
    await process_message(message)


@bot.event
async def on_raw_message_update(payload: discord.RawMessageUpdateEvent):
    """
    Webhook embeds can arrive as an edit — Discord sometimes sends the message
    first with no embeds, then updates it with the resolved embed.
    This handler catches those updates.
    """
    if payload.channel_id != WAZUH_CHANNEL_ID:
        return
    if payload.message_id in _triaged:
        return

    log.info(f"[on_raw_message_update] msg_id={payload.message_id} "
             f"channel={payload.channel_id} data_keys={list(payload.data.keys())}")

    # Only care about updates that add embeds
    embeds_data = payload.data.get("embeds", [])
    if not embeds_data:
        return

    channel = bot.get_channel(payload.channel_id)
    if not channel:
        return

    try:
        message = await channel.fetch_message(payload.message_id)
    except discord.HTTPException as e:
        log.warning(f"Could not fetch message {payload.message_id}: {e}")
        return

    await process_message(message)


@bot.event
async def on_error(event, *args, **kwargs):
    log.exception(f"Discord error in event {event}")


if __name__ == "__main__":
    bot.run(DISCORD_TOKEN, log_handler=None)
