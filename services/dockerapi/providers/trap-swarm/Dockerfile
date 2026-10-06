# AmberCell dockerapi hi-cell — Swarm manager surface trap (no dockerd).
# Provider id: trap-swarm — AMBER_DOCKERAPI_PROVIDER=trap-swarm
FROM python@sha256:1b668429b3511ab407d8e00648891631b0b1a4d7e15e3ca70f38ab5b91ad4ab4

WORKDIR /opt/trap
COPY trap_server.py /opt/trap/trap_server.py
COPY entrypoint.sh /entrypoint.sh
RUN chmod 755 /entrypoint.sh /opt/trap/trap_server.py

ENV AMBER_DOCKERAPI_PROVIDER=trap-swarm
ENV AMBER_DOCKERAPI_TRAP_PROFILE=swarm

EXPOSE 2375/tcp
ENTRYPOINT ["/entrypoint.sh"]
