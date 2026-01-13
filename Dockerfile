FROM node:20-alpine

WORKDIR /app

COPY package*.json ./

RUN apk add --no-cache python3 make g++ \
  && npm ci --omit=dev \
  && apk del python3 make g++   # เอาออกหลังติดตั้ง เพื่อลดขนาด (optional)

COPY . .

# ใส่เลขให้ตรงกับ Render ที่ใช้บ่อยในคุณ (ไม่บังคับ แต่ช่วยอ่านง่าย)
EXPOSE 10000

CMD ["npm", "start"]
