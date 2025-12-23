FROM node:20-slim

  WORKDIR /app

  COPY package*.json ./
  RUN npm install --omit=dev

  COPY . .

  ENV NODE_ENV=production
  ENV PORT=80
  EXPOSE 80

  CMD ["npm", "start"]