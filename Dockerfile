# Multi-stage Dockerfile for Hugging Face Spaces
# Combines FastAPI backend + Next.js frontend in one container

# --- Stage 1: Build frontend ---
FROM node:20-slim AS frontend-build

WORKDIR /app/web

COPY apps/web/package.json apps/web/package-lock.json* ./
RUN npm install --legacy-peer-deps

COPY apps/web/ ./

ENV NEXT_PUBLIC_API_HOST=""
ENV NEXT_TELEMETRY_DISABLED=1

RUN npm run build

# --- Stage 2: Final image ---
FROM python:3.12-slim

WORKDIR /app

# Install system deps (including nmap for port scanning)
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    nginx \
    nodejs \
    npm \
    nmap \
    unzip \
    curl \
    supervisor \
    && rm -rf /var/lib/apt/lists/*

# Install nuclei (ProjectDiscovery vulnerability scanner)
# Using the install script which auto-detects platform and latest release
RUN curl -sL https://raw.githubusercontent.com/projectdiscovery/nuclei/main/scripts/install.sh | sh \
    && mv nuclei /usr/local/bin/ 2>/dev/null || true \
    && nuclei -update-templates 2>/dev/null || true

# Install Python deps
COPY pyproject.toml .
RUN pip install --no-cache-dir . 2>/dev/null || pip install --no-cache-dir -e .

# Copy backend
COPY apps/api apps/api

# Copy built frontend
COPY --from=frontend-build /app/web/.next apps/web/.next
COPY --from=frontend-build /app/web/node_modules apps/web/node_modules
COPY --from=frontend-build /app/web/package.json apps/web/package.json
COPY --from=frontend-build /app/web/next.config.ts apps/web/next.config.ts
COPY --from=frontend-build /app/web/styles apps/web/styles
COPY --from=frontend-build /app/web/tsconfig.json apps/web/tsconfig.json

# Nginx config: proxy both services behind port 7860 (HF Spaces default)
RUN cat > /etc/nginx/sites-available/default << 'NGINX'
server {
    listen 7860;

    # Frontend
    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_read_timeout 86400;
    }

    # API backend
    location /api/ {
        proxy_pass http://127.0.0.1:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_read_timeout 86400;
    }
}
NGINX

# Supervisor config: run all 3 processes
RUN cat > /etc/supervisor/conf.d/redbrain.conf << 'SUPERVISOR'
[supervisord]
nodaemon=true
logfile=/dev/stdout
logfile_maxbytes=0

[program:backend]
command=uvicorn apps.api.main:app --host 127.0.0.1 --port 8000
directory=/app
autorestart=true
stdout_logfile=/dev/stdout
stdout_logfile_maxbytes=0
stderr_logfile=/dev/stderr
stderr_logfile_maxbytes=0

[program:frontend]
command=npx next start --port 3000
directory=/app/apps/web
autorestart=true
stdout_logfile=/dev/stdout
stdout_logfile_maxbytes=0
stderr_logfile=/dev/stderr
stderr_logfile_maxbytes=0

[program:nginx]
command=nginx -g "daemon off;"
autorestart=true
stdout_logfile=/dev/stdout
stdout_logfile_maxbytes=0
stderr_logfile=/dev/stderr
stderr_logfile_maxbytes=0
SUPERVISOR

EXPOSE 7860

CMD ["supervisord", "-c", "/etc/supervisor/supervisord.conf"]
