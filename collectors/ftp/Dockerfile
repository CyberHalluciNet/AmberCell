FROM ambercell-collector-base:latest

WORKDIR /opt/ambercell/ftp-collector

# Build context: repository root (see collectors/README.md).
COPY collectors/ftp/ftp_collector ./ftp_collector
# Seed mirror for RETR sha256 (hi image owns the live tree; collector hashes here).
COPY collectors/ftp/seeds /mnt/hi-seed

ENV AMBER_FTP_PROVIDER=vsftpd
ENV AMBER_FTP_CELL_IP=172.30.30.10
ENV AMBER_FTP_CELL_ID=ftp-cell-01
ENV AMBER_FTP_COLLECTOR_ID=ftp-collector-a
ENV AMBER_FTP_SEED_DIR=/mnt/hi-seed
ENV AMBER_FTP_UPLOAD_DIR=/mnt/hi-uploads

ENTRYPOINT ["python3", "-m", "ftp_collector.main"]
