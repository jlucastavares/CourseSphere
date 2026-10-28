# Etapa 1: gera a versão de produção do site (arquivos estáticos)
FROM node:20-alpine AS build
WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci

COPY . .
# A API é acessada pelo mesmo endereço do site, através do Nginx (/api).
ARG VITE_API_URL=/api
ENV VITE_API_URL=$VITE_API_URL
RUN npm run build

# Etapa 2: Nginx sem privilégios de root servindo os arquivos gerados.
# A imagem final não tem Node, código-fonte nem node_modules.
FROM nginxinc/nginx-unprivileged:1.31-alpine
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 8080
