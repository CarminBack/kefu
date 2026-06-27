FROM node:18-alpine

WORKDIR /app

COPY package*.json ./
RUN apk add --no-cache python3 make g++ && npm install --production

COPY . .

EXPOSE 19999

CMD ["node", "server.js"]
