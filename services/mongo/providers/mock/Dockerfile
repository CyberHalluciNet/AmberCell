# AmberCell Mongo hi-cell — wire-level mock (no real MongoDB)
# Provider id: mock — AMBER_MONGO_PROVIDER=mock
FROM python@sha256:1b668429b3511ab407d8e00648891631b0b1a4d7e15e3ca70f38ab5b91ad4ab4

WORKDIR /opt/mock
COPY mock_server.py /opt/mock/mock_server.py
COPY entrypoint.sh /entrypoint.sh
RUN chmod 755 /entrypoint.sh /opt/mock/mock_server.py

EXPOSE 27017/tcp
ENTRYPOINT ["/entrypoint.sh"]
