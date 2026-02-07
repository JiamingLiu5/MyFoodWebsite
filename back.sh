#!/bin/sh
set -eu

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
BACKUP_DIR="${1:-$ROOT_DIR/backups}"
TIMESTAMP="$(date +%F-%H%M%S)"

mkdir -p "$BACKUP_DIR"

DB_SOURCE="${DB_PATH:-}"
case "$DB_SOURCE" in
  "") ;;
  /*) ;;
  *) DB_SOURCE="$ROOT_DIR/$DB_SOURCE" ;;
esac

if [ -z "$DB_SOURCE" ] || [ ! -f "$DB_SOURCE" ]; then
  for candidate in "$ROOT_DIR/data/data.db" "$ROOT_DIR/data.db"; do
    if [ -f "$candidate" ]; then
      DB_SOURCE="$candidate"
      break
    fi
  done
fi

if [ -n "${DB_SOURCE:-}" ] && [ -f "$DB_SOURCE" ]; then
  DB_BACKUP="$BACKUP_DIR/data-$TIMESTAMP.db"
  if command -v sqlite3 >/dev/null 2>&1; then
    sqlite3 "$DB_SOURCE" ".backup \"$DB_BACKUP\""
  else
    cp "$DB_SOURCE" "$DB_BACKUP"
  fi
  echo "Database backup created: $DB_BACKUP"
else
  echo "No database file found. Skipping database backup."
fi

UPLOADS_SOURCE="${UPLOADS_DIR:-$ROOT_DIR/uploads}"
case "$UPLOADS_SOURCE" in
  /*) ;;
  *) UPLOADS_SOURCE="$ROOT_DIR/$UPLOADS_SOURCE" ;;
esac

if [ -d "$UPLOADS_SOURCE" ]; then
  UPLOADS_BACKUP="$BACKUP_DIR/uploads-$TIMESTAMP.tar.gz"
  tar -czf "$UPLOADS_BACKUP" -C "$UPLOADS_SOURCE" .
  echo "Uploads backup created: $UPLOADS_BACKUP"
else
  echo "No uploads directory found. Skipping uploads backup."
fi

echo "Backup completed."
