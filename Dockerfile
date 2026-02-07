FROM node:18-slim
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm install --production
COPY . .
RUN mkdir -p /app/uploads
EXPOSE 3000
CMD ["node","server.js"]
