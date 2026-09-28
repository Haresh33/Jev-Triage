# Jev Triage: one container with the UI, API and background worker. Data lives in /data.
FROM oven/bun:1.3.13-alpine

WORKDIR /app
ENV NODE_ENV=production

# Dependencies first, so code changes don't reinstall them.
COPY package.json bun.lock bunfig.toml ./
RUN bun install --frozen-lockfile --production

COPY tsconfig.base.json ./
COPY drizzle ./drizzle
COPY server ./server
COPY client ./client
COPY scripts ./scripts
# Starting memory and example cases, copied into /data on first start so approvals persist in the volume.
COPY memory ./defaults/memory
COPY eval ./defaults/eval

RUN mkdir -p /data && chown bun:bun /data
USER bun

# Inside the container the app listens on all interfaces; docker-compose publishes it on localhost only.
ENV HOST=0.0.0.0 PORT=3000 DATA_DIR=/data MEMORY_DIR=/data/memory EVAL_DIR=/data/eval
VOLUME ["/data"]
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s CMD wget -qO- http://127.0.0.1:3000/healthz >/dev/null || exit 1

# The cold-loop commands run inside the container too: docker compose exec jev-triage bun run eval
CMD ["sh", "-c", "[ -d /data/memory ] || cp -r defaults/memory /data/memory; [ -d /data/eval ] || cp -r defaults/eval /data/eval; exec bun server/src/server.ts"]
