#!/usr/bin/env bash
# install.sh — Instalação do Home Net Monitor
#
# Uso:
#   sudo bash install.sh
#
# O script:
#   1. Verifica dependências de sistema
#   2. Cria ambiente virtual Python
#   3. Instala pacotes Python
#   4. Configura permissões ICMP (cap_net_raw)
#   5. Instala serviço systemd
#   6. Inicia o serviço

set -euo pipefail

INSTALL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVICE_NAME="home-net-monitor"
SERVICE_USER="${SUDO_USER:-$USER}"
VENV_DIR="$INSTALL_DIR/.venv"
DATA_DIR="$INSTALL_DIR/data"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

info()    { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }

# ── 1. Verifica root ────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    error "Execute como root: sudo bash install.sh"
fi

info "Instalando Home Net Monitor em $INSTALL_DIR"
info "Usuário do serviço: $SERVICE_USER"

# ── 2. Verifica dependências de sistema ─────────────────────────────────────
for cmd in python3 pip3; do
    command -v "$cmd" &>/dev/null || error "Requer $cmd — instale com: apt install python3 python3-pip"
done

PYTHON_VER=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
if python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3,11) else 1)' 2>/dev/null; then
    info "Python $PYTHON_VER encontrado"
else
    error "Requer Python 3.11+. Encontrado: $PYTHON_VER"
fi

# Dependências opcionais de sistema
for pkg in iputils-ping arp-scan; do
    if ! dpkg -l "$pkg" &>/dev/null; then
        warn "Pacote $pkg não encontrado — instale com: apt install $pkg"
    fi
done

# ── 3. Ambiente virtual Python ───────────────────────────────────────────────
if [[ ! -d "$VENV_DIR" ]]; then
    info "Criando ambiente virtual em $VENV_DIR"
    python3 -m venv "$VENV_DIR"
fi

info "Instalando dependências Python..."
"$VENV_DIR/bin/pip" install --upgrade pip -q
"$VENV_DIR/bin/pip" install -r "$INSTALL_DIR/requirements.txt" -q
info "Dependências instaladas com sucesso"

# ── 4. Diretório de dados ───────────────────────────────────────────────────
mkdir -p "$DATA_DIR"
chown "$SERVICE_USER:$SERVICE_USER" "$DATA_DIR"

# ── 5. Permissão ICMP (cap_net_raw) ─────────────────────────────────────────
PYTHON_BIN="$VENV_DIR/bin/python3"
if command -v setcap &>/dev/null; then
    setcap cap_net_raw+ep "$PYTHON_BIN" && info "cap_net_raw configurado em $PYTHON_BIN" \
        || warn "Falha ao configurar cap_net_raw — ICMP pode exigir sudo"
else
    warn "setcap não encontrado — instale libcap2-bin: apt install libcap2-bin"
fi

# ── 6. Serviço systemd ───────────────────────────────────────────────────────
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
info "Instalando serviço systemd: $SERVICE_FILE"

cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=Home Net Monitor — Diagnóstico de rede doméstica
Documentation=https://github.com/JConradoN/home-net-monitor
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$SERVICE_USER
WorkingDirectory=$INSTALL_DIR
ExecStart=$VENV_DIR/bin/python main.py --config $INSTALL_DIR/config.json
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=home-net-monitor

# Limites de recursos (RNF01 — < 5% CPU)
CPUQuota=20%
MemoryMax=256M

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable "$SERVICE_NAME"
systemctl restart "$SERVICE_NAME"

# ── 7. Status final ─────────────────────────────────────────────────────────
sleep 2
if systemctl is-active --quiet "$SERVICE_NAME"; then
    info "Serviço $SERVICE_NAME iniciado com sucesso!"
    info ""
    info "  Dashboard: http://127.0.0.1:8080"
    info "  API Docs:  http://127.0.0.1:8080/api/docs"
    info "  Logs:      journalctl -u $SERVICE_NAME -f"
    info "  Parar:     systemctl stop $SERVICE_NAME"
else
    warn "Serviço pode ter falhado. Verifique: journalctl -u $SERVICE_NAME -n 50"
fi
