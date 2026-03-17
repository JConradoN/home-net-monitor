# Dockerfile — Home Net Monitor
# Build: docker build -t home-net-monitor .
# Run:   docker run --network host --cap-add NET_RAW home-net-monitor

FROM python:3.11-slim

# Dependências de sistema para ICMP (cap_net_raw), ARP scan e mDNS
RUN apt-get update && apt-get install -y --no-install-recommends \
    iputils-ping \
    arp-scan \
    net-tools \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Instala dependências Python
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copia código-fonte
COPY . .

# Cria diretório para banco de dados
RUN mkdir -p data

# Capacidade para ICMP raw sem root
# Requer --cap-add NET_RAW no docker run
RUN setcap cap_net_raw+ep /usr/bin/ping || true

EXPOSE 8080

# Variáveis de ambiente configuráveis
ENV HNM_HOST=127.0.0.1
ENV HNM_PORT=8080
ENV HNM_LOG_LEVEL=INFO

CMD ["python", "main.py"]
