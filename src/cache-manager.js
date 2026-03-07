const Redis = require('ioredis');

class CacheManager {
  constructor(options = {}) {
    this.enabled = options.enabled !== false;
    this.ttl = options.ttl || 300; // 5 minutes default
    this.redis = null;

    if (this.enabled && options.redisUrl) {
      try {
        this.redis = new Redis(options.redisUrl, {
          maxRetriesPerRequest: 3,
          enableReadyCheck: true,
          lazyConnect: true
        });

        this.redis.on('error', (err) => {
          console.error('[Cache] Redis error:', err.message);
        });

        this.redis.on('connect', () => {
          console.log('[Cache] Redis connected');
        });

        // Connect asynchronously
        this.redis.connect().catch((err) => {
          console.error('[Cache] Redis connection failed:', err.message);
          this.enabled = false;
        });
      } catch (err) {
        console.error('[Cache] Redis initialization failed:', err.message);
        this.enabled = false;
      }
    } else {
      console.log('[Cache] Redis caching disabled');
    }
  }

  async get(key) {
    if (!this.enabled || !this.redis) return null;

    try {
      const value = await this.redis.get(key);
      if (value) {
        return JSON.parse(value);
      }
    } catch (err) {
      console.error('[Cache] Get error:', err.message);
    }
    return null;
  }

  async set(key, value, ttl = null) {
    if (!this.enabled || !this.redis) return false;

    try {
      const serialized = JSON.stringify(value);
      const expiry = ttl || this.ttl;
      await this.redis.setex(key, expiry, serialized);
      return true;
    } catch (err) {
      console.error('[Cache] Set error:', err.message);
    }
    return false;
  }

  async del(key) {
    if (!this.enabled || !this.redis) return false;

    try {
      await this.redis.del(key);
      return true;
    } catch (err) {
      console.error('[Cache] Delete error:', err.message);
    }
    return false;
  }

  async delPattern(pattern) {
    if (!this.enabled || !this.redis) return false;

    try {
      const keys = await this.redis.keys(pattern);
      if (keys.length > 0) {
        await this.redis.del(...keys);
      }
      return true;
    } catch (err) {
      console.error('[Cache] Delete pattern error:', err.message);
    }
    return false;
  }

  async disconnect() {
    if (this.redis) {
      await this.redis.quit();
      console.log('[Cache] Redis disconnected');
    }
  }

  // Helper: wrap a database query with caching
  async wrap(key, fetchFn, ttl = null) {
    const cached = await this.get(key);
    if (cached !== null) {
      return cached;
    }

    const fresh = await fetchFn();
    await this.set(key, fresh, ttl);
    return fresh;
  }
}

module.exports = CacheManager;
