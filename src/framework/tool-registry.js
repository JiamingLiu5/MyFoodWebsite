class ToolRegistry {
  constructor() {
    this.toolsByKey = new Map();
  }

  register(toolDefinition) {
    if (!toolDefinition || typeof toolDefinition !== 'object') {
      throw new Error('Tool definition must be an object.');
    }

    const key = String(toolDefinition.key || '').trim();
    if (!key) throw new Error('Tool key is required.');
    if (!/^[a-z0-9_]+$/.test(key)) {
      throw new Error(`Invalid tool key "${key}". Use lowercase letters, numbers, and underscores only.`);
    }
    if (this.toolsByKey.has(key)) {
      throw new Error(`Duplicate tool key "${key}".`);
    }

    const name = String(toolDefinition.name || '').trim();
    const description = String(toolDefinition.description || '').trim();
    const inputFieldName = String(toolDefinition.inputFieldName || 'files').trim();
    if (!name) throw new Error(`Tool "${key}" is missing a name.`);
    if (!inputFieldName) throw new Error(`Tool "${key}" is missing an inputFieldName.`);
    if (typeof toolDefinition.createUploadMiddleware !== 'function') {
      throw new Error(`Tool "${key}" must provide createUploadMiddleware(multer).`);
    }
    if (typeof toolDefinition.run !== 'function') {
      throw new Error(`Tool "${key}" must provide an async run(context) function.`);
    }

    const normalized = {
      ...toolDefinition,
      key,
      name,
      description,
      inputFieldName,
      getMulterErrorMessage: typeof toolDefinition.getMulterErrorMessage === 'function'
        ? toolDefinition.getMulterErrorMessage
        : () => null,
      isExpectedError: typeof toolDefinition.isExpectedError === 'function'
        ? toolDefinition.isExpectedError
        : () => false
    };

    this.toolsByKey.set(key, normalized);
    return normalized;
  }

  get(toolKey) {
    const normalizedKey = String(toolKey || '').trim();
    if (!normalizedKey) return null;
    return this.toolsByKey.get(normalizedKey) || null;
  }

  list() {
    return Array.from(this.toolsByKey.values());
  }

  keys() {
    return Array.from(this.toolsByKey.keys());
  }
}

module.exports = {
  ToolRegistry
};
