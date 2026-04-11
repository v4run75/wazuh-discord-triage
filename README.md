# wazuh-discord-triage

Discord bot that watches your Wazuh alerts channel and automatically replies to each alert with an AI triage report from Claude.

## How it works

1. Wazuh posts an alert embed to your Discord channel
2. The bot detects it, extracts rule ID, level, agent, and full log
3. Sends it to Claude with a security analyst prompt
4. Replies in a **thread** on the original alert with a structured triage

Example triage for Rule 550 (FIM integrity change):
```
**What happened:** A scheduled task file was modified on Blood-G14 ...
**Verdict:** Likely true positive — hash change on a Windows system task ...
**Severity in context:** Medium-High. FIM changes on system32 tasks ...
**Recommended actions:**
  • Verify with the asset owner if a software update was applied
  • Check for recent logins on Blood-G14 around the timestamp
  • Compare against known-good baseline if available
**MITRE:** T1053.005 - Scheduled Task/Job: Scheduled Task
```

## Setup

### 1. Create Discord bot
1. Go to https://discord.com/developers/applications → New Application
2. Bot → Add Bot → copy token
3. OAuth2 → URL Generator → scopes: `bot` → permissions: `Send Messages`, `Create Public Threads`, `Read Message History`, `View Channels`
4. Invite the bot to your server using the generated URL
5. Enable **Message Content Intent** under Bot → Privileged Gateway Intents

### 2. Get channel ID
Right-click the Wazuh alerts channel → Copy Channel ID  
(Enable Developer Mode in Discord settings first)

### 3. Configure
```bash
cp .env.example .env
# Edit .env with your tokens and channel ID
```

### 4. Run on Raspberry Pi

```bash
# Build and start
docker compose up -d

# View logs
docker compose logs -f
```

### 4a. Or run without Docker
```bash
pip install -r requirements.txt
cp .env.example .env  # fill in values
cd bot && python main.py
```

## Environment variables

| Variable | Required | Description |
|---|---|---|
| `DISCORD_TOKEN` | Yes | Discord bot token |
| `WAZUH_CHANNEL_ID` | Yes | Channel ID where Wazuh posts alerts |
| `ANTHROPIC_API_KEY` | Yes | Claude API key |
| `TRIAGE_DELAY_SECONDS` | No | Delay before triaging (default: 2s) |

## Architecture

```
bot/
  main.py      Discord client, event handling, thread creation
  parser.py    Extracts structured data from Wazuh Discord embeds
  triage.py    Sends alert to Claude API, returns triage markdown
```

Supports all Wazuh rule levels. Thread is created on each alert message so triage replies stay organised alongside the original alert.
