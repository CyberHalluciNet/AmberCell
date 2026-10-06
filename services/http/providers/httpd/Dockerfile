# AmberCell HTTP hi-cell — Apache httpd
# Provider id: httpd — AMBER_HTTP_PROVIDER=httpd
FROM httpd:2.4-alpine

RUN mkdir -p /var/www/uploads
COPY httpd.conf /usr/local/apache2/conf/httpd.conf
COPY html/ /usr/local/apache2/htdocs/
COPY entrypoint.sh /entrypoint.sh
RUN chmod 755 /entrypoint.sh

EXPOSE 80/tcp 443/tcp
ENTRYPOINT ["/entrypoint.sh"]
