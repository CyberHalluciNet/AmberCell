# AmberCell Ollama hi-cell — real ollama serve (no auto model pulls)
# Provider id: ollama — AMBER_OLLAMA_PROVIDER=ollama
FROM ollama/ollama:0.5.7

USER root
COPY entrypoint.sh /entrypoint.sh
RUN chmod 755 /entrypoint.sh
ENV OLLAMA_HOST=0.0.0.0:11434
ENV OLLAMA_KEEP_ALIVE=0
# Do not pre-pull models in build; empty model store is intentional for labs.
ENTRYPOINT ["/entrypoint.sh"]
EXPOSE 11434/tcp
