'use strict';

/**
 * AI Chat provider abstraction.
 * Supports Claude (Anthropic), OpenAI, and custom OpenAI-compatible endpoints.
 * Uses native fetch() — no SDK dependencies.
 */

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
              messages: messages.map(m => ({ role: m.role, content: m.content }))
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
              messages: messages.map(m => ({ role: m.role, content: m.content }))
            })
          }
        };
      },
      parseSSELine: parseOpenAISSELine
    };
  }

  if (customLlmApiKey && customLlmBaseUrl) {
    const baseUrl = customLlmBaseUrl.replace(/\/+$/, '');
    const models = customLlmModels
      ? customLlmModels.split(',').map(m => m.trim()).filter(Boolean)
      : ['default'];
    providers.custom = {
      name: customLlmName || 'Custom',
      models,
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
              messages: messages.map(m => ({ role: m.role, content: m.content }))
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
 * @param {Array} messages - Array of {role, content} message objects
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

module.exports = { buildProviders, streamChatResponse };
