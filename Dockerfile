FROM node:lts-alpine

WORKDIR /app

COPY package*.json ./

RUN npm install

COPY . .

COPY ./competition.yaml /etc/sok/

ENV SOK_CONFIG=/etc/sok/competition.yaml

EXPOSE 8080

CMD npm start