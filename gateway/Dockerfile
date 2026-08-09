# The gateway needs a real browser, so the image carries one.
#
# Debian's chromium rather than the copy puppeteer downloads: it is patched by
# the distribution, it is the build that matches the system libraries already
# in the image, and it means `npm ci` does not pull 150 MB on every rebuild.
FROM node:20-bookworm-slim AS build

WORKDIR /app
ENV PUPPETEER_SKIP_DOWNLOAD=true

# better-sqlite3 compiles from source; those tools are not wanted in the
# runtime image, which is the whole reason this stage exists.
RUN apt-get update && apt-get install -y --no-install-recommends \
      python3 make g++ \
    && rm -rf /var/lib/apt/lists/*

COPY package*.json ./
RUN npm ci

COPY tsconfig.json ./
COPY src ./src
RUN npm run build && npm prune --omit=dev


FROM node:20-bookworm-slim AS runtime

ENV NODE_ENV=production \
    PUPPETEER_SKIP_DOWNLOAD=true \
    PUPPETEER_EXECUTABLE_PATH=/usr/bin/chromium \
    SESSION_PATH=/data/whatsapp \
    DATABASE_PATH=/data/gateway.db

# chromium plus the fonts it needs. Without the Hebrew-capable fonts the
# rendered page is boxes, which matters the day someone screenshots it to
# find out why a message did not go.
RUN apt-get update && apt-get install -y --no-install-recommends \
      chromium \
      fonts-liberation fonts-noto-core fonts-noto-color-emoji \
      ca-certificates dumb-init \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
COPY package.json ./

# The session is a live login. It belongs to one unprivileged user and to a
# volume, never to the image.
RUN mkdir -p /data && chown -R node:node /data /app
USER node
VOLUME ["/data"]

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=40s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||3000)+'/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

# dumb-init so SIGTERM reaches node and the shutdown path actually runs —
# otherwise Chromium is orphaned and the queue is killed mid-send.
ENTRYPOINT ["dumb-init", "--"]
CMD ["node", "dist/server.js"]
