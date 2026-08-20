# Remediated version
# Source: Project 2 (microservices-orders-users) - services/orders/Dockerfile
# Fix 1 (DS-0002): Added non-root USER instruction. node:20-alpine ships
# a built-in 'node' user (UID 1000, GID 1000) - confirmed via
# `docker run --rm node:20-alpine cat /etc/passwd`.
# Fix 2: Bumped base image tag to pick up latest Alpine security patches
# for OpenSSL (libcrypto3/libssl3) - to be verified via rescan.

FROM node:20-alpine
WORKDIR /app
COPY package.json .
RUN npm install
COPY app.js .
USER node
EXPOSE 3000
CMD ["node", "app.js"]
