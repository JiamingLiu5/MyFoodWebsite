#!/bin/sh
set -eu

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
BACKUP_DIR="$ROOT_DIR/backups"
DAYS_AGO="${1:-3}"
ASSUME_YES="${2:-}"

usage() {
  echo "Usage: sh timeback.sh [days_ago] [--yes]"
  echo "Example: sh timeback.sh 3 --yes"
}

is_integer() {
  case "$1" in
    ''|*[!0-9]*)
      return 1
      ;;
    *)
      return 0
      ;;
  esac
}

epoch_from_stamp() {
  stamp="$1"
  date_part="${stamp%-*}"
  time_part="${stamp##*-}"
  hh="$(printf '%s' "$time_part" | cut -c1-2)"
  mm="$(printf '%s' "$time_part" | cut -c3-4)"
  ss="$(printf '%s' "$time_part" | cut -c5-6)"
  iso="$date_part $hh:$mm:$ss"

  if date -j -f "%Y-%m-%d %H:%M:%S" "$iso" "+%s" >/dev/null 2>&1; then
    date -j -f "%Y-%m-%d %H:%M:%S" "$iso" "+%s"
    return 0
  fi

  if date -d "$iso" "+%s" >/dev/null 2>&1; then
    date -d "$iso" "+%s"
    return 0
  fi

  return 1
}

if ! is_integer "$DAYS_AGO"; then
  usage
  echo "Error: days_ago must be a non-negative integer."
  exit 1
fi

if [ ! -d "$BACKUP_DIR" ]; then
  echo "No backups directory found at $BACKUP_DIR"
  exit 1
fi

DB_TARGET="${DB_PATH:-}"
case "$DB_TARGET" in
  "") ;;
  /*) ;;
  *) DB_TARGET="$ROOT_DIR/$DB_TARGET" ;;
esac

if [ -z "$DB_TARGET" ]; then
  if [ -f "$ROOT_DIR/data/data.db" ] || [ -d "$ROOT_DIR/data" ]; then
    DB_TARGET="$ROOT_DIR/data/data.db"
  else
    DB_TARGET="$ROOT_DIR/data.db"
  fi
fi

now_epoch="$(date +%s)"
cutoff_epoch=$((now_epoch - DAYS_AGO * 86400))

selected_file=""
selected_epoch=0

for file in "$BACKUP_DIR"/data-*.db; do
  [ -e "$file" ] || continue
  base="$(basename "$file")"
  stamp="${base#data-}"
  stamp="${stamp%.db}"
  epoch="$(epoch_from_stamp "$stamp" || true)"
  [ -n "$epoch" ] || continue

  if [ "$epoch" -le "$cutoff_epoch" ] && [ "$epoch" -gt "$selected_epoch" ]; then
    selected_epoch="$epoch"
    selected_file="$file"
  fi
done

if [ -z "$selected_file" ]; then
  echo "No database backup found that is at least $DAYS_AGO day(s) old."
  echo "Available backups:"
  ls -1 "$BACKUP_DIR"/data-*.db 2>/dev/null || echo "  (none)"
  exit 1
fi

echo "Restore target: $DB_TARGET"
echo "Selected backup: $selected_file"

if [ "$ASSUME_YES" != "--yes" ]; then
  printf "Type YES to restore database: "
  read -r reply
  if [ "$reply" != "YES" ]; then
    echo "Cancelled."
    exit 0
  fi
fi

mkdir -p "$(dirname "$DB_TARGET")"
now_stamp="$(date +%F-%H%M%S)"

if [ -f "$DB_TARGET" ]; then
  safety_file="$BACKUP_DIR/pre-restore-$now_stamp.db"
  if command -v sqlite3 >/dev/null 2>&1; then
    sqlite3 "$DB_TARGET" ".backup \"$safety_file\""
  else
    cp "$DB_TARGET" "$safety_file"
  fi
  echo "Safety backup created: $safety_file"
fi

cp "$selected_file" "$DB_TARGET"
echo "Database restored from: $selected_file"
echo "Done."
