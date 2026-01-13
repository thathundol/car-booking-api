# ใช้ Node LTS
FROM node:20-alpine

WORKDIR /app

# ติดตั้ง dependency ก่อนเพื่อ cache layer
COPY package*.json ./

# sqlite3 บน alpine บางครั้งต้อง build tool เพิ่ม
RUN apk add --no-cache python3 make g++ \
  && npm ci --omit=dev

# คัดลอกโค้ดเข้ามา
COPY . .

# Render จะส่ง PORT มาให้ เราแค่ expose ไว้
EXPOSE 3000

# สั่งรัน
CMD ["npm", "start"]
