#!/bin/bash
# Daily export of the production D1 database.
#
# Run by a launchd agent once a day, and safe to run by hand at any time:
#   npm run backup            (or ./scripts/backup-db.sh)
#
# Where it writes, and why not straight into ~/Downloads:
#
#   macOS will not let a scheduled job read or write inside Downloads,
#   Documents or Desktop unless the thing running it has been granted Full
#   Disk Access. A backup that quietly fails every night at 21:00 is worse
#   than no backup, and granting Full Disk Access to /bin/bash to avoid that
#   is a poor trade. So the job lives entirely outside those folders, and
#   ~/Downloads/Tzayad(30.7)/auto is a symlink pointing here — the files show
#   up where you look for them, without anything needing new permissions.
#
#   Nothing from the project directory is needed either: wrangler finds the
#   database by name from the account, and its login sits in ~/Library.
#
# What this file is careful about:
#
#   * The hand-made backup next door is not ours to prune. We only ever touch
#     files we wrote, in our own folder.
#   * The export goes to a temporary name and is checked before it counts.
#     A truncated download or an expired login produces a small or empty file,
#     and pruning good backups on the strength of a bad one is how a backup
#     system becomes the thing that loses the data.
#   * Only after a good file lands does it delete anything, and never below
#     KEEP surviving copies.
#
# The file holds the wrapped private key. It stays on this machine.

set -uo pipefail

DEST="$HOME/Library/Application Support/Tzayad/backups"
LOG="$DEST/backup.log"
KEEP=14
MIN_BYTES=100000            # a real export is megabytes; anything this small is a failure

mkdir -p "$DEST"
say() { printf '%s  %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$1" >> "$LOG"; }

stamp="$(date '+%Y-%m-%d')"
tmp="$DEST/.tmp-$stamp.sql"
out="$DEST/db-$stamp.sql"

rm -f "$tmp"
# One level up: wrangler drops a .wrangler working directory wherever it runs,
# and the backup folder should hold backups and nothing else.
cd "$(dirname "$DEST")" || exit 1

# launchd starts with almost no PATH, and a Node upgrade moves the one this was
# installed against. Say so plainly rather than logging "command not found".
command -v npx >/dev/null 2>&1 || {
  say "FAIL: npx is not on PATH — fix PATH in ~/Library/LaunchAgents/com.tzayad.backup.plist"
  exit 1
}

# Pinned to the major version the project uses. No project directory is
# involved, so this is the one thing that has to name a version.
if ! npx --yes wrangler@4 d1 export tzayad --remote --output "$tmp" >> "$LOG" 2>&1; then
  say "FAIL: wrangler export failed — check the login (npx wrangler login)"
  rm -f "$tmp"
  exit 1
fi

size=$(stat -f%z "$tmp" 2>/dev/null || echo 0)
if [ "$size" -lt "$MIN_BYTES" ]; then
  say "FAIL: export is only ${size}B — kept the previous backups, deleted nothing"
  rm -f "$tmp"
  exit 1
fi

# A valid export declares the tables the data lives in. If those are missing,
# whatever downloaded is not a backup of this database.
for table in records reports vault users; do
  if ! grep -q "CREATE TABLE $table" "$tmp"; then
    say "FAIL: export has no '$table' table — kept the previous backups, deleted nothing"
    rm -f "$tmp"
    exit 1
  fi
done

mv -f "$tmp" "$out"
say "OK: $(basename "$out") (${size} bytes)"

# Prune, oldest first, and only ever inside this folder.
count=$(ls -1 "$DEST"/db-*.sql 2>/dev/null | wc -l | tr -d ' ')
if [ "$count" -gt "$KEEP" ]; then
  ls -1t "$DEST"/db-*.sql | tail -n +$((KEEP + 1)) | while read -r old; do
    rm -f "$old"
    say "pruned $(basename "$old")"
  done
fi

# Keep the log from growing forever.
if [ -f "$LOG" ] && [ "$(wc -l < "$LOG")" -gt 2000 ]; then
  tail -n 500 "$LOG" > "$LOG.trim" && mv -f "$LOG.trim" "$LOG"
fi
