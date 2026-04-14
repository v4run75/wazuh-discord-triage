# wazuh-discord-triage

Discord bot that watches your Wazuh alerts channel and automatically replies to each alert with an AI triage report. Uses [OpenRouter](https://openrouter.ai) — one API key, access to hundreds of models including free tiers.

## How it works

1. Wazuh posts an alert embed to your Discord channel
2. The bot detects it, extracts rule ID, level, agent, and full log
3. Sends it to an LLM via OpenRouter with a security analyst prompt
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

### 3. Get an OpenRouter API key
Sign up at [openrouter.ai](https://openrouter.ai/keys) — free tier available with models like `meta-llama/llama-3.1-8b-instruct:free`.

### 4. Configure
```bash
cp .env.example .env
# Set DISCORD_TOKEN, WAZUH_CHANNEL_ID, OPENROUTER_API_KEY
```

### 5. Run on Raspberry Pi

```bash
# Build and start
docker compose up -d

# View logs
docker compose logs -f
```

### 5a. Or run without Docker
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
| `OPENROUTER_API_KEY` | Yes | OpenRouter API key |
| `OPENROUTER_MODEL` | No | Model slug (default: `meta-llama/llama-3.1-8b-instruct:free`) |
| `TRIAGE_DELAY_SECONDS` | No | Delay before triaging (default: 2s) |

### Recommended models on OpenRouter
| Model | Cost | Quality |
|---|---|---|
| `meta-llama/llama-3.1-8b-instruct:free` | Free | Good |
| `mistralai/mistral-7b-instruct:free` | Free | Good |
| `meta-llama/llama-3.1-70b-instruct` | ~$0.001/alert | Better |
| `anthropic/claude-3.5-sonnet` | ~$0.01/alert | Best |

## Architecture

```
bot/
  main.py      Discord client, event handling, thread creation
  parser.py    Extracts structured data from Wazuh Discord embeds
  triage.py    Sends alert to LLM (Ollama/OpenAI-compatible), returns triage markdown
```

Supports all Wazuh rule levels. Thread is created on each alert message so triage replies stay organised alongside the original alert.

Uses the OpenAI Python SDK pointing at OpenRouter's API. Swap models anytime by changing `OPENROUTER_MODEL` — no code changes needed.
