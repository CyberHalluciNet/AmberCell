FROM ambercell-collector-base:latest

WORKDIR /opt/ambercell/kubelet-collector
COPY collectors/kubelet/kubelet_collector ./kubelet_collector

ENV AMBER_KUBELET_PROVIDER=trap
ENV AMBER_KUBELET_CELL_IP=172.30.150.10

ENTRYPOINT ["python3", "-m", "kubelet_collector.main"]
