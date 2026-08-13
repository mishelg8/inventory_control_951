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

APP="$HOME/Library/Application Support/Tzayad"
DEST="$APP/backups"
LOG="$DEST/backup.log"
TOOLS="$APP/tools"          # wrangler lives here, installed once — see below
WRANGLER="$TOOLS/node_modules/.bin/wrangler"
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
cd "$APP" || exit 1

# launchd starts with almost no PATH, and a Node upgrade moves the one this was
# installed against. Say so plainly rather than logging "command not found".
command -v node >/dev/null 2>&1 || {
  say "FAIL: node is not on PATH — fix PATH in ~/Library/LaunchAgents/com.tzayad.backup.plist"
  exit 1
}

# wrangler is installed here once and then simply run.
#
# This used to be `npx --yes wrangler@4`, which re-resolved the package against
# registry.npmjs.org on every single run. On the night of 12 August 2026 that
# fetch timed out, the whole run died before it ever reached Cloudflare, and
# the day had no backup — a nightly dependency on a third party that the job
# has no reason to need. The project directory cannot help: it lives in
# ~/Downloads, which is exactly what a scheduled job is not allowed to read.
# So the tool lives in the job's own folder, beside the backups it takes.
#
# Pinned to the major version the project uses. No project directory is
# involved, so this is the one thing that has to name a version.
if [ ! -x "$WRANGLER" ]; then
  say "wrangler is not installed here yet — installing wrangler@4 into $TOOLS"
  mkdir -p "$TOOLS"
  [ -f "$TOOLS/package.json" ] || printf '{"private":true}\n' > "$TOOLS/package.json"
  if ! npm install --prefix "$TOOLS" --no-audit --no-fund wrangler@4 >> "$LOG" 2>&1; then
    say "FAIL: could not install wrangler into $TOOLS — no export attempted, deleted nothing"
    exit 1
  fi
fi

# One retry. The export is a download of several megabytes over a link that
# occasionally drops it, and losing a day's backup to a single dropped
# connection is the failure this job exists to prevent.
export_ok=0
for attempt in 1 2; do
  if "$WRANGLER" d1 export tzayad --remote --output "$tmp" >> "$LOG" 2>&1; then
    export_ok=1
    break
  fi
  rm -f "$tmp"
  [ "$attempt" = 1 ] && { say "export attempt 1 failed — retrying in 60s"; sleep 60; }
done

if [ "$export_ok" != 1 ]; then
  # Deliberately not "check the login". It said that for a year, and when the
  # job finally did fail the message sent the reader to a login that was fine.
  # The wrangler output is directly above this line in the log; read that.
  say "FAIL: wrangler export failed twice — the reason is in the wrangler output above"
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
