# AmberCell Ollama hi-cell — LocalAI OpenAI-compatible (CPU)
# Provider id: localai — AMBER_OLLAMA_PROVIDER=localai
FROM localai/localai:v2.25.0-ffmpeg-core

USER root
COPY entrypoint.sh /entrypoint.sh
RUN chmod 755 /entrypoint.sh
ENV ADDRESS=0.0.0.0:11434
ENV MODELS_PATH=/models
ENV DEBUG=true
ENTRYPOINT ["/entrypoint.sh"]
EXPOSE 11434/tcp
