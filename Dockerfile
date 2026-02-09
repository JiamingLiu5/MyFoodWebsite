FROM node:18-slim
WORKDIR /app
RUN apt-get update \
  && apt-get install -y --no-install-recommends ffmpeg \
  && rm -rf /var/lib/apt/lists/*
COPY package.json package-lock.json* ./
RUN npm install --production
COPY . .
RUN mkdir -p /app/uploads
EXPOSE 3000
CMD ["node","server.js"]
