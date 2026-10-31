# KillChain web: build the React app, then serve it with nginx on 8080.
# nginx proxies /api/ to the api service, so the build talks to /api (same origin, no CORS).
FROM node:20-alpine AS build
WORKDIR /web
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY . .
ENV VITE_API_URL=/api
# vite build only: `npm run build` also type-checks the tests, which import examples/ from
# outside web/ (not in this build context). Type checks run with `npm run build` locally.
RUN npx vite build

FROM nginx:1.27-alpine
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /web/dist /usr/share/nginx/html
EXPOSE 8080
HEALTHCHECK --interval=10s --timeout=3s --retries=5 CMD wget -q -O /dev/null http://127.0.0.1:8080/ || exit 1
