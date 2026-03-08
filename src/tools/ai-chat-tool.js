'use strict';

/**
 * AI Chat provider abstraction.
 * Supports Claude (Anthropic), OpenAI, and custom OpenAI-compatible endpoints.
 * Uses native fetch() — no SDK dependencies.
 */

/**
 * Format messages for a specific provider type, handling multimodal content.
 * @param {Array} messages - Array of {role, content, images?} where images is [{base64, mimetype}]
 * @param {'claude'|'openai'} type - Provider type
 */
function formatMessagesForProvider(messages, type) {
  return messages.map(m => {
    const images = m.images && m.images.length > 0 ? m.images : null;
    if (!images) {
      return { role: m.role, content: m.content };
    }

    if (type === 'claude') {
      const content = [];
      for (const img of images) {
        content.push({
          type: 'image',
          source: { type: 'base64', media_type: img.mimetype, data: img.base64 }
        });
      }
      if (m.content) {
        content.push({ type: 'text', text: m.content });
      }
      return { role: m.role, content };
    }

    // OpenAI / Custom (OpenAI-compatible)
    const content = [];
    for (const img of images) {
      content.push({
        type: 'image_url',
        image_url: { url: `data:${img.mimetype};base64,${img.base64}` }
      });
    }
    if (m.content) {
      content.push({ type: 'text', text: m.content });
    }
    return { role: m.role, content };
  });
}

function buildProviders({ anthropicApiKey, openaiApiKey, customLlmApiKey, customLlmBaseUrl, customLlmModels, customLlmName }) {
  const providers = {};

  if (anthropicApiKey) {
    providers.claude = {
      name: 'Claude',
      models: ['claude-sonnet-4-20250514', 'claude-haiku-4-5-20251001'],
      buildRequest(messages, model) {
        return {
          url: 'https://api.anthropic.com/v1/messages',
          options: {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'x-api-key': anthropicApiKey,
              'anthropic-version': '2023-06-01'
            },
            body: JSON.stringify({
              model,
              max_tokens: 4096,
              stream: true,
              messages: formatMessagesForProvider(messages, 'claude')
            })
          }
        };
      },
      parseSSELine(data) {
        try {
          const parsed = JSON.parse(data);
          if (parsed.type === 'content_block_delta' && parsed.delta?.text) {
            return parsed.delta.text;
          }
          if (parsed.type === 'message_stop') {
            return null; // signals done
          }
          if (parsed.type === 'error') {
            throw new Error(parsed.error?.message || 'Claude API error');
          }
        } catch (e) {
          if (e.message !== 'Claude API error' && !(e instanceof SyntaxError)) throw e;
        }
        return undefined; // no text in this line
      }
    };
  }

  if (openaiApiKey) {
    providers.openai = {
      name: 'OpenAI',
      models: ['gpt-4o', 'gpt-4o-mini'],
      buildRequest(messages, model) {
        return {
          url: 'https://api.openai.com/v1/chat/completions',
          options: {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'Authorization': `Bearer ${openaiApiKey}`
            },
            body: JSON.stringify({
              model,
              stream: true,
              messages: formatMessagesForProvider(messages, 'openai')
            })
          }
        };
      },
      parseSSELine: parseOpenAISSELine
    };
  }

  if (customLlmApiKey && customLlmBaseUrl) {
    const baseUrl = customLlmBaseUrl.replace(/\/+$/, '');
    const fallbackModels = customLlmModels
      ? customLlmModels.split(',').map(m => m.trim()).filter(Boolean)
      : [];
    providers.custom = {
      name: customLlmName || 'Custom',
      models: fallbackModels.length ? fallbackModels : ['default'],
      _baseUrl: baseUrl,
      _apiKey: customLlmApiKey,
      _fallbackModels: fallbackModels,
      buildRequest(messages, model) {
        return {
          url: `${baseUrl}/v1/chat/completions`,
          options: {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'Authorization': `Bearer ${customLlmApiKey}`
            },
            body: JSON.stringify({
              model,
              stream: true,
              messages: formatMessagesForProvider(messages, 'openai')
            })
          }
        };
      },
      parseSSELine: parseOpenAISSELine
    };
  }

  return providers;
}

function parseOpenAISSELine(data) {
  if (data === '[DONE]') return null;
  try {
    const parsed = JSON.parse(data);
    const content = parsed.choices?.[0]?.delta?.content;
    if (content) return content;
    if (parsed.choices?.[0]?.finish_reason) return null;
  } catch (e) {
    // ignore parse errors for non-JSON lines
  }
  return undefined;
}

/**
 * Stream a chat response from the given provider.
 * @param {object} provider - Provider object from buildProviders()
 * @param {Array} messages - Array of {role, content, images?} message objects
 * @param {string} model - Model ID to use
 * @param {object} callbacks - { onChunk(text), onDone(fullText), onError(err), signal }
 */
async function streamChatResponse(provider, messages, model, { onChunk, onDone, onError, signal }) {
  let fullText = '';
  try {
    const { url, options } = provider.buildRequest(messages, model);
    const response = await fetch(url, { ...options, signal });

    if (!response.ok) {
      const errorBody = await response.text();
      let errorMessage;
      try {
        const parsed = JSON.parse(errorBody);
        errorMessage = parsed.error?.message || parsed.message || `API error ${response.status}`;
      } catch {
        errorMessage = `API error ${response.status}: ${errorBody.slice(0, 200)}`;
      }
      throw new Error(errorMessage);
    }

    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let buffer = '';

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;

      buffer += decoder.decode(value, { stream: true });
      const lines = buffer.split('\n');
      buffer = lines.pop(); // keep incomplete line in buffer

      for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed || !trimmed.startsWith('data:')) continue;
        const data = trimmed.slice(5).trim();
        if (!data) continue;

        const text = provider.parseSSELine(data);
        if (text === null) {
          // stream complete
          onDone(fullText);
          return;
        }
        if (text !== undefined) {
          fullText += text;
          onChunk(text);
        }
      }
    }

    // If we exited the loop without a done signal, finish up
    onDone(fullText);
  } catch (err) {
    if (err.name === 'AbortError') return;
    onError(err);
  }
}

/**
 * Fetch available models from a custom provider's /v1/models endpoint.
 * Updates the provider's models list in-place. Falls back to env var models on error.
 * Results are cached for 5 minutes.
 */
let _customModelsCache = null;
let _customModelsCacheTime = 0;
const MODELS_CACHE_TTL = 5 * 60 * 1000;

async function refreshCustomModels(provider) {
  if (!provider || !provider._baseUrl) return;

  const now = Date.now();
  if (_customModelsCache && (now - _customModelsCacheTime) < MODELS_CACHE_TTL) {
    provider.models = _customModelsCache;
    return;
  }

  try {
    const res = await fetch(`${provider._baseUrl}/v1/models`, {
      headers: provider._apiKey ? { 'Authorization': `Bearer ${provider._apiKey}` } : {},
      signal: AbortSignal.timeout(5000)
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    const models = (data.data || data)
      .map(m => typeof m === 'string' ? m : m.id)
      .filter(Boolean)
      .sort();
    if (models.length > 0) {
      _customModelsCache = models;
      _customModelsCacheTime = now;
      provider.models = models;
    }
  } catch (err) {
    console.error('Failed to fetch custom models:', err.message);
    // Keep existing models (env var fallback or previous cache)
  }
}

module.exports = { buildProviders, streamChatResponse, refreshCustomModels };
