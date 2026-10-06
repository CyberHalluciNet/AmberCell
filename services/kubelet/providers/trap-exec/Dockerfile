# AmberCell kubelet hi-cell — exec/attach-focused trap (no cluster).
# Provider id: trap-exec — AMBER_KUBELET_PROVIDER=trap-exec
FROM python@sha256:1b668429b3511ab407d8e00648891631b0b1a4d7e15e3ca70f38ab5b91ad4ab4

WORKDIR /opt/trap
COPY trap_server.py /opt/trap/trap_server.py
COPY entrypoint.sh /entrypoint.sh
RUN chmod 755 /entrypoint.sh /opt/trap/trap_server.py

ENV AMBER_KUBELET_PROVIDER=trap-exec
ENV AMBER_KUBELET_TRAP_PROFILE=exec

EXPOSE 10250/tcp
ENTRYPOINT ["/entrypoint.sh"]
