# AmberCell Elastic hi-cell — ZincSearch (lightweight, Apache-2.0)
# Provider id: zincsearch — AMBER_ELASTIC_PROVIDER=zincsearch
FROM public.ecr.aws/zinclabs/zincsearch:0.4.15

USER root
COPY entrypoint-wrap.sh /entrypoint-wrap.sh
RUN chmod 755 /entrypoint-wrap.sh

ENV ZINC_SERVER_MODE=node
ENV ZINC_DATA_PATH=/data
ENV ZINC_FIRST_ADMIN_USER=admin
ENV ZINC_FIRST_ADMIN_PASSWORD=ambercell
# Listen on 9200 to match elastic cell port contract
ENV ZINC_SERVER_PORT=9200

ENTRYPOINT ["/entrypoint-wrap.sh"]
EXPOSE 9200/tcp
