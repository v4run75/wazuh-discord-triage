"""
main.py — Discord bot that watches Wazuh alerts and posts a triage button in a thread.
Triage only runs when a user clicks the button — no automatic API calls.
"""

import os
import asyncio
import logging
import discord
from discord import ui
from dotenv import load_dotenv

from parser import parse_embed, parse_text, WazuhAlert
from triage import triage_alert

load_dotenv()
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("wazuh-triage")

logging.getLogger("discord.gateway").setLevel(logging.WARNING)
logging.getLogger("discord.http").setLevel(logging.WARNING)

DISCORD_TOKEN    = os.environ["DISCORD_TOKEN"]
WAZUH_CHANNEL_ID = int(os.environ["WAZUH_CHANNEL_ID"])

intents = discord.Intents.default()
intents.message_content = True
intents.messages = True

bot = discord.Client(intents=intents)

# Track message IDs we've already opened a thread for
_seen: set[int] = set()


def severity_color(level: int) -> discord.Color:
    if level >= 12: return discord.Color.dark_red()
    if level >= 9:  return discord.Color.orange()
    if level >= 6:  return discord.Color.yellow()
    if level >= 3:  return discord.Color.blue()
    return discord.Color.greyple()


class TriageView(ui.View):
    """Persistent view with a single Triage button. Disabled after first use."""

    def __init__(self, alert: WazuhAlert):
        super().__init__(timeout=None)
        self.alert = alert

    @ui.button(label="Triage with AI", style=discord.ButtonStyle.primary, emoji="🤖")
    async def triage_button(self, interaction: discord.Interaction, button: ui.Button):
        # Disable the button immediately so it can't be double-clicked
        button.disabled = True
        button.label = "Triaging..."
        await interaction.response.edit_message(view=self)

        async with interaction.channel.typing():
            try:
                loop = asyncio.get_event_loop()
                triage_text = await loop.run_in_executor(None, triage_alert, self.alert)
            except Exception as e:
                log.error(f"Triage error: {e}")
                button.label = "Triage Failed"
                await interaction.edit_original_response(view=self)
                await interaction.channel.send(
                    embed=discord.Embed(
                        title="⚠️ Triage Failed",
                        description=f"`{e}`",
                        color=discord.Color.red(),
                    )
                )
                return

        button.label = "Triaged"
        await interaction.edit_original_response(view=self)

        embed = discord.Embed(
            title=f"🤖 AI Triage · Rule {self.alert.rule_id}",
            description=triage_text,
            color=severity_color(self.alert.rule_level),
        )
        embed.add_field(name="Agent", value=f"`{self.alert.agent_name}` ({self.alert.agent_ip})", inline=True)
        embed.add_field(name="Level", value=f"`{self.alert.rule_level}` {self.alert.severity}", inline=True)
        embed.add_field(name="Rule",  value=self.alert.rule_description or "—", inline=False)
        embed.set_footer(text=f"Triaged by AI · Manager: {self.alert.manager}")

        await interaction.channel.send(embed=embed)
        log.info(f"Triage posted: rule={self.alert.rule_id} agent={self.alert.agent_name}")


async def process_message(message: discord.Message):
    """Parse a Wazuh alert and open a thread with a triage button."""
    if message.author == bot.user:
        return

    log.info(
        f"[RAW] author={message.author!r} webhook_id={message.webhook_id} "
        f"embeds={len(message.embeds)} content={message.content[:80]!r}"
    )

    alert = None

    for embed in message.embeds:
        alert = parse_embed(embed)
        if alert:
            log.info(f"Parsed via embed: rule={alert.rule_id} level={alert.rule_level} agent={alert.agent_name}")
            break

    if not alert and message.content:
        alert = parse_text(message.content)
        if alert:
            log.info(f"Parsed via text: rule={alert.rule_id} level={alert.rule_level} agent={alert.agent_name}")

    if not alert:
        log.info("Message did not match Wazuh alert format — skipped")
        return

    _seen.add(message.id)

    thread_name = f"Rule {alert.rule_id} · {alert.agent_name}"[:100]
    try:
        thread = await message.create_thread(
            name=thread_name,
            auto_archive_duration=1440,
        )
    except discord.HTTPException as e:
        log.warning(f"Could not create thread ({e}) — skipping")
        return

    summary = (
        f"**Rule {alert.rule_id}** — {alert.rule_description or 'No description'}\n"
        f"Agent: `{alert.agent_name}` ({alert.agent_ip}) · Level: `{alert.rule_level}` {alert.severity}"
    )
    await thread.send(content=summary, view=TriageView(alert))
    log.info(f"Thread created with triage button: rule={alert.rule_id} agent={alert.agent_name}")


@bot.event
async def on_ready():
    log.info(f"Logged in as {bot.user} (id={bot.user.id})")
    log.info(f"Watching channel id={WAZUH_CHANNEL_ID}")
    log.info(f"Guilds: {[f'{g.name} (id={g.id})' for g in bot.guilds]}")
    channel = bot.get_channel(WAZUH_CHANNEL_ID)
    if channel:
        log.info(f"Channel found: #{channel.name} in {channel.guild.name}")
        perms = channel.permissions_for(channel.guild.me)
        log.info(f"Permissions: send={perms.send_messages} read={perms.read_messages} "
                 f"read_history={perms.read_message_history} threads={perms.create_public_threads}")
    else:
        log.error(f"Channel {WAZUH_CHANNEL_ID} NOT FOUND")
        log.error(f"Visible channels: {[(c.name, c.id) for g in bot.guilds for c in g.channels]}")


@bot.event
async def on_message(message: discord.Message):
    log.info(f"[on_message] channel={message.channel.id} author={message.author} "
             f"webhook_id={message.webhook_id} embeds={len(message.embeds)}")

    if message.channel.id != WAZUH_CHANNEL_ID:
        return
    if message.id in _seen:
        return
    await process_message(message)


@bot.event
async def on_raw_message_update(payload: discord.RawMessageUpdateEvent):
    if payload.channel_id != WAZUH_CHANNEL_ID:
        return
    if payload.message_id in _seen:
        return
    if not payload.data.get("embeds"):
        return

    log.info(f"[on_raw_message_update] msg_id={payload.message_id}")

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
