#!/bin/bash
# Installs (or re-installs) the daily backup job.
#
#   npm run backup:install
#
# The script in this repository is the original. macOS will not let a
# scheduled job read anything inside ~/Downloads, so a copy is installed into
# ~/Library/Application Support/Tzayad/ and that copy is what launchd runs —
# run this again after editing backup-db.sh, or the change will not take.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP="$HOME/Library/Application Support/Tzayad"
PLIST="$HOME/Library/LaunchAgents/com.tzayad.backup.plist"
NODE_BIN="$(dirname "$(command -v node)")"

mkdir -p "$APP/backups" "$HOME/Library/LaunchAgents"
cp "$HERE/backup-db.sh" "$APP/backup-db.sh"
chmod +x "$APP/backup-db.sh"

# wrangler, installed once into the job's own folder rather than fetched from
# the registry every night. The nightly fetch is what lost the 12 August 2026
# backup. Doing it here means the first scheduled run already has its tool.
mkdir -p "$APP/tools"
[ -f "$APP/tools/package.json" ] || printf '{"private":true}\n' > "$APP/tools/package.json"
npm install --prefix "$APP/tools" --no-audit --no-fund wrangler@4

cat > "$PLIST" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<!--
  Daily backup of the Tzayad production database.
  Written by scripts/install-backup.sh — edit that, not this.

  Stop it:    launchctl unload -w ~/Library/LaunchAgents/com.tzayad.backup.plist
  Start it:   launchctl load -w ~/Library/LaunchAgents/com.tzayad.backup.plist
  Run it now: launchctl kickstart gui/\$(id -u)/com.tzayad.backup
-->
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.tzayad.backup</string>

  <key>ProgramArguments</key>
  <array>
    <string>/bin/bash</string>
    <string>$APP/backup-db.sh</string>
  </array>

  <!-- launchd hands over almost no environment; Node has to be findable. -->
  <key>EnvironmentVariables</key>
  <dict>
    <key>PATH</key>
    <string>$NODE_BIN:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin</string>
    <key>HOME</key>
    <string>$HOME</string>
  </dict>

  <!-- 21:00 every day. A run missed because the Mac was asleep happens on wake. -->
  <key>StartCalendarInterval</key>
  <dict>
    <key>Hour</key><integer>21</integer>
    <key>Minute</key><integer>0</integer>
  </dict>

  <key>RunAtLoad</key>
  <false/>

  <key>StandardOutPath</key>
  <string>$APP/backups/launchd.log</string>
  <key>StandardErrorPath</key>
  <string>$APP/backups/launchd.log</string>
</dict>
</plist>
PLIST

plutil -lint "$PLIST" >/dev/null
launchctl unload "$PLIST" 2>/dev/null || true
launchctl load -w "$PLIST"

echo "installed: $APP/backup-db.sh"
echo "scheduled: every day at 21:00 (com.tzayad.backup)"
echo "backups:   $APP/backups"
