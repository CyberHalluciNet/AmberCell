# AmberCell dockerapi hi-cell — API trap only (G4/G8). No docker.sock, no dockerd.
# Provider id: trap — AMBER_DOCKERAPI_PROVIDER=trap
FROM python@sha256:1b668429b3511ab407d8e00648891631b0b1a4d7e15e3ca70f38ab5b91ad4ab4

WORKDIR /opt/trap
COPY trap_server.py /opt/trap/trap_server.py
COPY entrypoint.sh /entrypoint.sh
RUN chmod 755 /entrypoint.sh /opt/trap/trap_server.py

EXPOSE 2375/tcp
# privileged: false — enforced in compose; never mount host engine socket.
ENTRYPOINT ["/entrypoint.sh"]
