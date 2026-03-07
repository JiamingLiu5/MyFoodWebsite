const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');
const sqlite3 = require('sqlite3').verbose();

class BackupManager {
  constructor(options = {}) {
    this.dbPath = options.dbPath || path.join(__dirname, '..', 'data.db');
    this.uploadsDir = options.uploadsDir || path.join(__dirname, '..', 'uploads');
    this.backupDir = options.backupDir || path.join(__dirname, '..', 'backups');
    this.intervalHours = options.intervalHours || 24;
    this.maxBackups = options.maxBackups || 7;
    this.enabled = options.enabled !== false;
    this.timer = null;
    this.isRunning = false;
  }

  start() {
    if (!this.enabled) {
      console.log('[Backup] Auto-backup is disabled');
      return;
    }

    console.log(`[Backup] Starting auto-backup (every ${this.intervalHours} hours, keeping ${this.maxBackups} backups)`);

    // Run initial backup after 1 minute
    setTimeout(() => this.runBackup(), 60000);

    // Schedule periodic backups
    const intervalMs = this.intervalHours * 60 * 60 * 1000;
    this.timer = setInterval(() => this.runBackup(), intervalMs);
  }

  stop() {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
      console.log('[Backup] Auto-backup stopped');
    }
  }

  async runBackup() {
    if (this.isRunning) {
      console.log('[Backup] Backup already in progress, skipping');
      return;
    }

    this.isRunning = true;
    const timestamp = this.getTimestamp();

    try {
      console.log('[Backup] Starting backup...');

      // Ensure backup directory exists
      if (!fs.existsSync(this.backupDir)) {
        fs.mkdirSync(this.backupDir, { recursive: true });
      }

      // Backup database
      await this.backupDatabase(timestamp);

      // Backup uploads
      await this.backupUploads(timestamp);

      // Clean old backups
      await this.cleanOldBackups();

      console.log('[Backup] Backup completed successfully');
    } catch (error) {
      console.error('[Backup] Backup failed:', error.message);
    } finally {
      this.isRunning = false;
    }
  }

  async backupDatabase(timestamp) {
    if (!fs.existsSync(this.dbPath)) {
      console.log('[Backup] Database file not found, skipping');
      return;
    }

    const backupPath = path.join(this.backupDir, `data-${timestamp}.db`);

    return new Promise((resolve, reject) => {
      const sourceDb = new sqlite3.Database(this.dbPath, sqlite3.OPEN_READONLY, (err) => {
        if (err) {
          reject(new Error(`Failed to open database: ${err.message}`));
          return;
        }

        const backup = sourceDb.backup(backupPath);

        backup.step(-1, (err) => {
          if (err) {
            sourceDb.close();
            reject(new Error(`Database backup failed: ${err.message}`));
            return;
          }

          backup.finish((err) => {
            sourceDb.close((closeErr) => {
              if (err) {
                reject(new Error(`Database backup finish failed: ${err.message}`));
              } else if (closeErr) {
                reject(new Error(`Failed to close database: ${closeErr.message}`));
              } else {
                console.log(`[Backup] Database backed up to: ${backupPath}`);
                resolve();
              }
            });
          });
        });
      });
    });
  }

  async backupUploads(timestamp) {
    if (!fs.existsSync(this.uploadsDir)) {
      console.log('[Backup] Uploads directory not found, skipping');
      return;
    }

    const backupPath = path.join(this.backupDir, `uploads-${timestamp}.tar.gz`);

    return new Promise((resolve, reject) => {
      const tar = spawn('tar', ['-czf', backupPath, '-C', this.uploadsDir, '.']);

      tar.on('close', (code) => {
        if (code === 0) {
          console.log(`[Backup] Uploads backed up to: ${backupPath}`);
          resolve();
        } else {
          reject(new Error(`Uploads backup failed with code ${code}`));
        }
      });

      tar.on('error', (err) => {
        reject(new Error(`Uploads backup error: ${err.message}`));
      });
    });
  }

  async cleanOldBackups() {
    const files = fs.readdirSync(this.backupDir);

    const dbBackups = files
      .filter(f => f.startsWith('data-') && f.endsWith('.db'))
      .sort()
      .reverse();

    const uploadBackups = files
      .filter(f => f.startsWith('uploads-') && f.endsWith('.tar.gz'))
      .sort()
      .reverse();

    // Keep only the most recent backups
    const toDelete = [
      ...dbBackups.slice(this.maxBackups),
      ...uploadBackups.slice(this.maxBackups)
    ];

    for (const file of toDelete) {
      try {
        fs.unlinkSync(path.join(this.backupDir, file));
        console.log(`[Backup] Deleted old backup: ${file}`);
      } catch (err) {
        console.error(`[Backup] Failed to delete ${file}:`, err.message);
      }
    }
  }

  getTimestamp() {
    const now = new Date();
    const year = now.getFullYear();
    const month = String(now.getMonth() + 1).padStart(2, '0');
    const day = String(now.getDate()).padStart(2, '0');
    const hours = String(now.getHours()).padStart(2, '0');
    const minutes = String(now.getMinutes()).padStart(2, '0');
    const seconds = String(now.getSeconds()).padStart(2, '0');
    return `${year}-${month}-${day}-${hours}${minutes}${seconds}`;
  }

  // Manual backup trigger
  async triggerBackup() {
    return this.runBackup();
  }
}

module.exports = BackupManager;
