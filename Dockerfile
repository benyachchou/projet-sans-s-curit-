FROM node:20-alpine

# Install curl for healthchecks
RUN apk add --no-cache curl

WORKDIR /usr/src/app

# Copy package manifests and install deps
COPY package.json package-lock.json ./
RUN npm ci --only=production

# Copy source code
COPY src ./src
COPY .env.example ./

# Environment
ENV NODE_ENV=production

# Create data dir (SQLite) and ensure it exists
RUN mkdir -p /data

# Expose default port
EXPOSE 3000

# Default command (node app)
CMD ["node", "src/index.js"]