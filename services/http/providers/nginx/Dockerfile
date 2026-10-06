# AmberCell HTTP hi-cell — default nginx provider
# Provider id: nginx — AMBER_HTTP_PROVIDER=nginx
FROM nginx:1.27-alpine

RUN apk add --no-cache bash

COPY nginx.conf /etc/nginx/nginx.conf
COPY html/ /usr/share/nginx/html/
COPY entrypoint.sh /entrypoint.sh
RUN chmod 755 /entrypoint.sh

EXPOSE 80/tcp 443/tcp
ENTRYPOINT ["/entrypoint.sh"]
