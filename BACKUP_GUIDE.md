# Auto-Backup Guide

## Overview

The application now includes automatic backup functionality that runs periodically to protect your data.

## What Gets Backed Up

- **Database**: SQLite database file (`data.db`)
- **Uploads**: All uploaded files in the `uploads/` directory

## Configuration

Set these environment variables in your `.env` file:

```bash
# Enable or disable auto-backup (default: true)
BACKUP_ENABLED=true

# Hours between automatic backups (default: 24)
BACKUP_INTERVAL_HOURS=24

# Number of backups to keep (default: 7)
BACKUP_MAX_KEEP=7
```

## How It Works

1. **First Backup**: Runs 1 minute after server starts
2. **Periodic Backups**: Runs every `BACKUP_INTERVAL_HOURS` hours
3. **Automatic Cleanup**: Keeps only the most recent `BACKUP_MAX_KEEP` backups
4. **Graceful Shutdown**: Stops backup timer when server shuts down

## Backup Files

Backups are stored in `./backups/` with timestamped filenames:

- `data-YYYY-MM-DD-HHMMSS.db` - Database backup
- `uploads-YYYY-MM-DD-HHMMSS.tar.gz` - Uploads backup

Example:
```
backups/
├── data-2026-03-07-120000.db
├── uploads-2026-03-07-120000.tar.gz
├── data-2026-03-08-120000.db
└── uploads-2026-03-08-120000.tar.gz
```

## Manual Backup

You can still use the existing backup scripts:

```bash
# Create a manual backup
sh back.sh

# Restore from a backup (3 days ago or older)
sh timeback.sh 3

# Non-interactive restore
sh timeback.sh 3 --yes
```

## Monitoring

Check server logs for backup status:

```
[Backup] Starting auto-backup (every 24 hours, keeping 7 backups)
[Backup] Starting backup...
[Backup] Database backed up to: backups/data-2026-03-07-120000.db
[Backup] Uploads backed up to: backups/uploads-2026-03-07-120000.tar.gz
[Backup] Deleted old backup: data-2026-02-28-120000.db
[Backup] Backup completed successfully
```

## Disabling Auto-Backup

To disable auto-backup, set in your `.env`:

```bash
BACKUP_ENABLED=false
```

The server will still start normally, but automatic backups won't run.

## Recommendations

- **Development**: `BACKUP_INTERVAL_HOURS=24` (daily)
- **Production**: `BACKUP_INTERVAL_HOURS=6` (every 6 hours)
- **Keep at least**: `BACKUP_MAX_KEEP=7` (one week of backups)

## Troubleshooting

**Backup fails with "Database file not found"**
- Check that `DB_PATH` environment variable is set correctly
- Verify the database file exists

**Backup fails with "tar command not found"**
- Install tar on your system (usually pre-installed on macOS/Linux)

**Old backups not being deleted**
- Check file permissions on the `backups/` directory
- Verify `BACKUP_MAX_KEEP` is set to a reasonable number
