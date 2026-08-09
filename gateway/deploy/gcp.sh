#!/usr/bin/env bash
#
# מקים את שער הוואטסאפ של מסייעת 951 על מכונה חינמית ב-Google Cloud.
#
# מריצים ב-Google Cloud Shell:   bash gcp.sh
#
# הוא בונה מכונת e2-micro (השכבה החינמית הקבועה של גוגל), מוסיף swap,
# מתקין Docker, מעלה את השער, ומרים Cloudflare Tunnel — כך שאף פורט
# נכנס לא נפתח לאינטרנט. אפשר להריץ אותו שוב; כל שלב מדלג על עצמו אם
# הוא כבר בוצע.
#
set -euo pipefail

# ── מה שאפשר לשנות ─────────────────────────────────────────────────
NAME="${NAME:-tzayad-gw}"
ZONE="${ZONE:-us-central1-a}"          # חייב us-west1 / us-central1 / us-east1
MACHINE="${MACHINE:-e2-micro}"         # כל דבר אחר יוצא מהשכבה החינמית
DISK_GB="${DISK_GB:-30}"               # 30 הוא המקסימום החינמי
SWAP_GB="${SWAP_GB:-3}"                # למכונה יש 1GB זיכרון. Chromium צריך יותר.
REPO="${REPO:-https://github.com/mishelg8/inventory_control_951.git}"
SRC="${SRC:-$HOME/tzayad}"

say()  { printf '\n\033[1m▸ %s\033[0m\n' "$*"; }
warn() { printf '\033[33m  ! %s\033[0m\n' "$*"; }
die()  { printf '\n\033[31m✖ %s\033[0m\n' "$*" >&2; exit 1; }

command -v gcloud >/dev/null || die 'אין gcloud. הריצו את הסקריפט ב-Google Cloud Shell.'

PROJECT="$(gcloud config get-value project 2>/dev/null || true)"
[ -n "$PROJECT" ] && [ "$PROJECT" != '(unset)' ] || die 'לא הוגדר פרויקט. הריצו: gcloud config set project <PROJECT_ID>'
say "פרויקט: $PROJECT · אזור: $ZONE · מכונה: $MACHINE"

# ── 1. הפעלת ה-API ─────────────────────────────────────────────────
say '1/6  מוודא שה-API של Compute פעיל'
gcloud services enable compute.googleapis.com --quiet

# ── 2. המכונה ──────────────────────────────────────────────────────
# אין כאן חוקי firewall נכנסים בכוונה. השער מאזין על 127.0.0.1 בלבד,
# והמנהרה של Cloudflare יוצאת החוצה — אין מה לסרוק מבחוץ.
STARTUP='#!/bin/bash
set -e
exec >>/var/log/tzayad-startup.log 2>&1
echo "=== startup $(date -Is) ==="

if [ ! -f /swapfile ]; then
  fallocate -l __SWAP__G /swapfile
  chmod 600 /swapfile
  mkswap /swapfile
  swapon /swapfile
  echo "/swapfile none swap sw 0 0" >> /etc/fstab
  # 1GB of RAM and a browser: lean on swap early rather than meet the OOM killer.
  sysctl -w vm.swappiness=60
  echo "vm.swappiness=60" > /etc/sysctl.d/99-tzayad.conf
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y docker.io docker-compose-v2 git unattended-upgrades curl
systemctl enable --now docker
dpkg-reconfigure -f noninteractive unattended-upgrades || true

if ! command -v cloudflared >/dev/null; then
  curl -fsSL -o /tmp/cloudflared.deb \
    https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64.deb
  dpkg -i /tmp/cloudflared.deb || apt-get -f install -y
  rm -f /tmp/cloudflared.deb
fi

mkdir -p /opt/tzayad
touch /var/lib/tzayad-ready
echo "=== startup done $(date -Is) ==="
'
STARTUP="${STARTUP//__SWAP__/$SWAP_GB}"

if gcloud compute instances describe "$NAME" --zone "$ZONE" >/dev/null 2>&1; then
  say "2/6  המכונה $NAME כבר קיימת — מדלג"
else
  say "2/6  יוצר את המכונה (זה לוקח כדקה)"
  SFILE="$(mktemp)"
  printf '%s' "$STARTUP" > "$SFILE"
  trap 'rm -f "$SFILE"' EXIT
  # בלי חשבון שירות ובלי הרשאות: המכונה הזאת לא צריכה לדבר עם שום API
  # של גוגל, וסוד שאין לה אי אפשר לגנוב ממנה.
  gcloud compute instances create "$NAME" \
    --zone "$ZONE" \
    --machine-type "$MACHINE" \
    --image-family ubuntu-2404-lts-amd64 \
    --image-project ubuntu-os-cloud \
    --boot-disk-size "${DISK_GB}GB" \
    --boot-disk-type pd-standard \
    --metadata-from-file "startup-script=$SFILE" \
    --no-service-account --no-scopes \
    --quiet
  rm -f "$SFILE"; trap - EXIT
fi

IP="$(gcloud compute instances describe "$NAME" --zone "$ZONE" \
      --format='get(networkInterfaces[0].accessConfigs[0].natIP)')"
say "כתובת: ${IP:-(אין)}"

# ── 3. המתנה לסיום ההתקנה שרצה בתוך המכונה ────────────────────────
say '3/6  ממתין שההתקנה במכונה תסתיים (Docker, swap, cloudflared)'
for i in $(seq 1 60); do
  if gcloud compute ssh "$NAME" --zone "$ZONE" --quiet \
       --command 'test -f /var/lib/tzayad-ready' >/dev/null 2>&1; then
    echo '  מוכן.'
    break
  fi
  printf '  ...%s\n' "$i"
  sleep 10
  [ "$i" = 60 ] && die 'ההתקנה לא הסתיימה. בדקו: gcloud compute ssh '"$NAME"' --zone '"$ZONE"' --command "sudo tail -40 /var/log/tzayad-startup.log"'
done

# ── 4. קוד השער ────────────────────────────────────────────────────
say '4/6  מביא את קוד השער'
if [ -d "$SRC/.git" ]; then
  git -C "$SRC" pull --ff-only || warn 'לא הצלחתי לעדכן — ממשיך עם מה שיש'
else
  echo '  ייתכן שתתבקשו להזדהות מול GitHub — זה אתם, לא הסקריפט.'
  git clone "$REPO" "$SRC"
fi
[ -d "$SRC/gateway" ] || die "לא נמצאה תיקיית gateway תחת $SRC"

say '     מעתיק למכונה'
gcloud compute ssh "$NAME" --zone "$ZONE" --quiet --command 'sudo mkdir -p /opt/tzayad && sudo chown -R $USER /opt/tzayad'
# node_modules ו-dist נבנים מחדש בתוך התמונה; אין טעם להעביר אותם.
tar czf /tmp/gateway.tgz -C "$SRC" \
  --exclude gateway/node_modules --exclude gateway/dist --exclude gateway/.env \
  gateway
gcloud compute scp /tmp/gateway.tgz "$NAME:/opt/tzayad/" --zone "$ZONE" --quiet
rm -f /tmp/gateway.tgz
gcloud compute ssh "$NAME" --zone "$ZONE" --quiet \
  --command 'cd /opt/tzayad && tar xzf gateway.tgz && rm gateway.tgz'

# ── 5. הגדרה והרצה ─────────────────────────────────────────────────
say '5/6  מגדיר ומריץ'
# הסוד נוצר על המכונה ולא עובר דרך הלוג של הסקריפט. אם כבר יש .env,
# הוא נשאר — החלפת הסוד מנתקת את הקונסולה מהשער.
gcloud compute ssh "$NAME" --zone "$ZONE" --quiet --command '
  set -e
  cd /opt/tzayad/gateway
  if [ ! -f .env ]; then
    cp .env.example .env
    SECRET=$(openssl rand -hex 32)
    sed -i "s|^API_SECRET=.*|API_SECRET=$SECRET|" .env
    sed -i "s|^TRUST_PROXY=.*|TRUST_PROXY=1|" .env
  fi
  sudo docker compose up -d --build
  sudo docker compose ps
'

say '     ממתין לבדיקת הבריאות'
gcloud compute ssh "$NAME" --zone "$ZONE" --quiet --command '
  for i in $(seq 1 30); do
    if curl -fsS http://127.0.0.1:3000/health >/dev/null 2>&1; then echo "  ✓ השער עונה"; exit 0; fi
    sleep 5
  done
  echo "  ✖ השער לא עונה. לוג:"; sudo docker compose -f /opt/tzayad/gateway/docker-compose.yml logs --tail 40; exit 1
'

# ── 6. המנהרה ──────────────────────────────────────────────────────
say '6/6  Cloudflare Tunnel'
cat <<'HOWTO'
  בדשבורד של Cloudflare:
    Zero Trust ← Networks ← Tunnels ← Create a tunnel ← Cloudflared
    תנו לו שם, ואז העתיקו את הטוקן מהפקודה שמוצגת (המחרוזת הארוכה אחרי --token).
    ב-Public Hostname: בחרו תת-דומיין, Service = HTTP, URL = localhost:3000

  ואז הדביקו כאן את הטוקן (הוא לא יוצג על המסך):
HOWTO
read -rsp '  TOKEN: ' TUNNEL_TOKEN; echo
if [ -n "${TUNNEL_TOKEN:-}" ]; then
  gcloud compute ssh "$NAME" --zone "$ZONE" --quiet \
    --command "sudo cloudflared service install '$TUNNEL_TOKEN' && sudo systemctl enable --now cloudflared && sleep 3 && sudo systemctl is-active cloudflared"
  echo '  ✓ המנהרה עלתה'
else
  warn 'דילגתם על המנהרה. השער רץ אבל אינו נגיש מבחוץ.'
  warn "להמשך אחר כך: gcloud compute ssh $NAME --zone $ZONE --command \"sudo cloudflared service install <TOKEN>\""
fi

# ── סיום ───────────────────────────────────────────────────────────
say 'סיימנו. מה שנשאר לעשות בידיים:'
cat <<EOF

  1. הסוד. הדפיסו אותו והעתיקו:
       gcloud compute ssh $NAME --zone $ZONE --command 'grep ^API_SECRET /opt/tzayad/gateway/.env'

  2. ב-Cloudflare Pages ← הפרויקט ← Settings ← Environment variables:
       WA_GATEWAY_URL     = הכתובת הציבורית שהגדרתם במנהרה
       WA_GATEWAY_SECRET  = אותו API_SECRET בדיוק
     ואז Deployments ← Retry deployment, אחרת המשתנים לא נטענים.

  3. קונסולה ← וואטסאפ ← חיבור, וסורקים את ה-QR מהטלפון של הקו.

  פקודות שימושיות:
    gcloud compute ssh $NAME --zone $ZONE
    gcloud compute ssh $NAME --zone $ZONE --command 'sudo docker compose -f /opt/tzayad/gateway/docker-compose.yml logs -f'
    gcloud compute instances stop $NAME --zone $ZONE      # עוצר את החיוב על המכונה
    gcloud compute instances delete $NAME --zone $ZONE     # מוחק הכל

EOF
