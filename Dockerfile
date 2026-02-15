FROM node:22-slim

ENV NODE_ENV=production
WORKDIR /app
RUN apt-get update \
  && apt-get install -y --no-install-recommends ffmpeg ghostscript \
  && rm -rf /var/lib/apt/lists/*
COPY package.json package-lock.json* ./
RUN npm ci --omit=dev
COPY . .
RUN mkdir -p /app/uploads /app/data \
  && chown -R node:node /app
EXPOSE 3000
CMD ["node","server.js"]
