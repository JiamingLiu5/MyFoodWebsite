# AI Chat Tool

AI chat assistant supporting Claude (Anthropic), OpenAI, and custom OpenAI-compatible providers with streaming responses.

## Usage

1. Navigate to **Tools** (`/tools`)
2. Click **Open AI Chat**
3. Select a provider and model from the dropdowns
4. Type a message and press **Enter** (or click **Send**)
5. The AI response streams in real-time

### Conversations

- Click **+ New Chat** to start a fresh conversation
- Past conversations are listed in the sidebar
- Click a conversation to resume it
- Click **x** on a conversation to delete it
- Conversations auto-title based on your first message

### Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `Enter` | Send message |
| `Shift + Enter` | New line |

## Requirements

- At least one AI provider API key configured
- Admin must grant "AI Chat" access to the user via User Management
- Node.js 22+ (uses native `fetch()`)

## Providers

### Claude (Anthropic)

| Setting | Value |
|---------|-------|
| Endpoint | `https://api.anthropic.com/v1/messages` |
| Models | `claude-sonnet-4-20250514`, `claude-haiku-4-5-20251001` |
| Max tokens | 4096 |

```env
ANTHROPIC_API_KEY=sk-ant-...
```

### OpenAI

| Setting | Value |
|---------|-------|
| Endpoint | `https://api.openai.com/v1/chat/completions` |
| Models | `gpt-4o`, `gpt-4o-mini` |

```env
OPENAI_API_KEY=sk-...
```

### Custom Provider

Any OpenAI-compatible API (e.g., OpenRouter, Ollama, LM Studio, vLLM).

| Setting | Value |
|---------|-------|
| Endpoint | `{CUSTOM_LLM_BASE_URL}/v1/chat/completions` |
| Models | Auto-discovered from `{CUSTOM_LLM_BASE_URL}/v1/models` |

Models are fetched automatically when you open the chat page (cached for 5 minutes). If the models endpoint is unavailable, it falls back to `CUSTOM_LLM_MODELS` from the env var.

```env
CUSTOM_LLM_API_KEY=your-key
CUSTOM_LLM_BASE_URL=https://openrouter.ai/api
CUSTOM_LLM_MODELS=model-a,model-b   # optional fallback if /v1/models is unavailable
CUSTOM_LLM_NAME=OpenRouter
```

## Configuration

Add to `.env`:

```env
# Enable/disable the feature (default: true)
AI_CHAT_ENABLED=true

# Provider API keys (at least one required)
ANTHROPIC_API_KEY=
OPENAI_API_KEY=

# Custom OpenAI-compatible provider (optional)
CUSTOM_LLM_API_KEY=
CUSTOM_LLM_BASE_URL=
CUSTOM_LLM_MODELS=
CUSTOM_LLM_NAME=

# Limits
AI_CHAT_MAX_MESSAGE_LENGTH=16000
AI_CHAT_RATE_LIMIT_WINDOW_SECONDS=60
AI_CHAT_RATE_LIMIT_MAX_SENDS=10
```

## Limits

| Limit | Default | Env Variable |
|-------|---------|-------------|
| Max message length | 16,000 characters | `AI_CHAT_MAX_MESSAGE_LENGTH` |
| Rate limit | 10 messages / 60 seconds | `AI_CHAT_RATE_LIMIT_MAX_SENDS` / `AI_CHAT_RATE_LIMIT_WINDOW_SECONDS` |

## Security

- API keys are stored server-side only, never exposed to the client
- CSRF protection on all requests
- Users can only access their own conversations
- Rate limiting prevents message spam
- Client disconnects abort upstream API calls (saves API credits)

## Database

Two tables store conversation data:

- `ai_conversations` — metadata (title, provider, model, timestamps)
- `ai_messages` — message history (role, content, timestamps)

Data is stored locally in the SQLite database.
