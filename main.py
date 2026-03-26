"""
main.py — Ponto de entrada do Home Net Monitor.

Inicializa todos os coletores, o motor de correlação, o repositório SQLite,
o EventBus SSE e sobe o servidor FastAPI/Uvicorn.

Fluxo de inicialização:
  1. Carrega configuração (config.json ou variáveis de ambiente)
  2. Inicializa banco de dados SQLite (WAL mode)
  3. Auto-detecta gateway e resolver DNS interno
  4. Instancia coletores (ICMP, DNS, SNMP, Fingerprint)
  5. Instancia Correlator + Recommender + EventBus
  6. Cria app FastAPI com rotas REST e endpoint SSE
  7. Sobe Uvicorn em localhost:8080

Uso:
    python main.py
    python main.py --port 8080 --host 127.0.0.1
    python main.py --config config.json
"""

import argparse
import asyncio
import logging
import sys
from pathlib import Path

# ─── Logging ─────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("home_net_monitor.log", encoding="utf-8"),
    ],
)
logger = logging.getLogger("hnm")


# ─── Config ───────────────────────────────────────────────────────────────────

DEFAULT_CONFIG = {
    "host": "127.0.0.1",          # RNF06 — apenas localhost
    "port": 8080,
    "db_path": "data/home_net_monitor.db",
    "icmp_interval": 30,           # segundos entre coletas ICMP
    "dns_interval": 60,
    "snmp_interval": 60,
    "fingerprint_interval": 300,
    "snmp_host": None,             # Detectado automaticamente se None
    "snmp_community": "public",
    "log_level": "INFO",
}


def load_config(config_path: Path = None) -> dict:
    """
    Carrega configuração do arquivo JSON ou retorna defaults.

    Args:
        config_path: Caminho para config.json. Se None, usa DEFAULT_CONFIG.

    Returns:
        Dicionário de configuração mesclado com defaults.
    """
    import json

    config = DEFAULT_CONFIG.copy()
    if config_path and config_path.exists():
        try:
            with open(config_path) as f:
                user_config = json.load(f)
            config.update(user_config)
            logger.info("Configuração carregada de %s", config_path)
        except Exception as exc:
            logger.warning("Falha ao carregar config: %s — usando defaults", exc)
    return config


# ─── App Factory ─────────────────────────────────────────────────────────────

def create_app(config: dict, components: dict = None):
    """
    Cria e configura a aplicação FastAPI.

    Registra:
      - Rotas REST (/api/*)
      - Endpoint SSE (/api/events)
      - Servir arquivos estáticos (frontend/)
      - Página inicial (index.html)

    Args:
        config:     Dicionário de configuração.
        components: Componentes inicializados por startup() (coletores, engine, db).

    Returns:
        fastapi.FastAPI configurado.
    """
    from fastapi import FastAPI, Request
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.responses import HTMLResponse, JSONResponse
    from fastapi.staticfiles import StaticFiles
    from fastapi.templating import Jinja2Templates

    app = FastAPI(
        title="Home Net Monitor",
        version="1.0.0",
        description="Monitor de rede doméstica — diagnóstico offline de gargalos",
        docs_url="/api/docs",
        redoc_url="/api/redoc",
    )

    # CORS — apenas localhost (RNF06)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["GET", "POST"],
        allow_headers=["*"],
    )

    # Rotas REST + SSE
    if components:
        from api.routes import create_router
        router = create_router(
            correlator=components.get("correlator"),
            recommender=components.get("recommender"),
            icmp_collector=components.get("icmp_collector"),
            dns_collector=components.get("dns_collector"),
            snmp_collector=components.get("snmp_collector"),
            fingerprint_collector=components.get("fingerprint_collector"),
            wifi_collector=components.get("wifi_collector"),
            db=components.get("db"),
            event_bus=components.get("event_bus"),
        )
        app.include_router(router)

    # Arquivos estáticos (CSS, JS)
    static_dir = Path(__file__).parent / "frontend" / "static"
    if static_dir.exists():
        app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    # Dashboard HTML
    templates_dir = Path(__file__).parent / "frontend" / "templates"
    if templates_dir.exists():
        templates = Jinja2Templates(directory=str(templates_dir))

        @app.get("/", response_class=HTMLResponse, include_in_schema=False)
        async def dashboard(request: Request):
            return templates.TemplateResponse(request, "index.html")
    else:
        @app.get("/", include_in_schema=False)
        async def root():
            return JSONResponse({"name": "Home Net Monitor", "version": "1.0.0", "docs": "/api/docs"})

    # Handler de erros genérico
    @app.exception_handler(Exception)
    async def generic_exception_handler(request, exc):
        logger.error("Erro não tratado: %s", exc)
        return JSONResponse(status_code=500, content={"detail": "Erro interno"})

    logger.info("App FastAPI configurada — host: %s:%s", config["host"], config["port"])
    return app


# ─── Lifecycle ────────────────────────────────────────────────────────────────

async def startup(config: dict):
    """
    Lifecycle de startup: inicializa todos os componentes.

    Args:
        config: Configuração carregada.
    """
    logger.info("╔══════════════════════════════════╗")
    logger.info("║     Home Net Monitor v1.0        ║")
    logger.info("╚══════════════════════════════════╝")

    # 1. Banco de dados
    from db.repository import Repository
    db = Repository(db_path=Path(config["db_path"]))
    await db.initialize()

    # 2. EventBus SSE
    from api.sse import EventBus, MetricsBroadcaster
    event_bus = EventBus()

    # 3. Motor de correlação + recomendações
    from engine.correlator import Correlator
    from engine.recommender import Recommender
    correlator = Correlator(event_bus=event_bus)
    recommender = Recommender()

    # 4. Coletores
    from collectors.icmp import ICMPCollector
    from collectors.dns import DNSCollector
    from collectors.fingerprint import FingerprintCollector
    from collectors.wifi import WiFiCollector

    icmp_collector = ICMPCollector(interval=config["icmp_interval"], db=db)
    dns_collector = DNSCollector(interval=config["dns_interval"], db=db)
    fingerprint_collector = FingerprintCollector(interval=config["fingerprint_interval"], db=db)
    wifi_collector = WiFiCollector(
        interface=config.get("wifi_interface"),
        interval=config.get("wifi_interval", 30),
        scan_neighbors=config.get("wifi_scan_neighbors", False),
    )

    # SNMP — apenas se host configurado ou detectável
    snmp_collector = None
    if config.get("snmp_host"):
        from collectors.snmp import SNMPCollector
        snmp_collector = SNMPCollector(
            host=config["snmp_host"],
            community=config["snmp_community"],
            interval=config["snmp_interval"],
            db=db,
        )
        logger.info("SNMP habilitado para %s", config["snmp_host"])

    # 5. MetricsBroadcaster (SSE)
    broadcaster = MetricsBroadcaster(
        event_bus=event_bus,
        icmp_collector=icmp_collector,
        snmp_collector=snmp_collector,
        dns_collector=dns_collector,
        wifi_collector=wifi_collector,
    )

    # 6. Inicia coletores como tasks asyncio
    tasks = [
        asyncio.create_task(icmp_collector.start(), name="icmp"),
        asyncio.create_task(dns_collector.start(), name="dns"),
        asyncio.create_task(fingerprint_collector.start(), name="fingerprint"),
        asyncio.create_task(wifi_collector.start(), name="wifi"),
        asyncio.create_task(broadcaster.start(), name="sse-broadcast"),
    ]
    if snmp_collector:
        tasks.append(asyncio.create_task(snmp_collector.start(), name="snmp"))

    logger.info("Todos os coletores iniciados (%d tasks)", len(tasks))

    return {
        "db": db,
        "event_bus": event_bus,
        "correlator": correlator,
        "recommender": recommender,
        "icmp_collector": icmp_collector,
        "dns_collector": dns_collector,
        "snmp_collector": snmp_collector,
        "fingerprint_collector": fingerprint_collector,
        "wifi_collector": wifi_collector,
        "tasks": tasks,
    }


async def run_collection_loop(components: dict, interval: float = 30.0):
    """
    Loop principal de correlação: a cada ciclo de coleta,
    monta um CorrelationSnapshot e passa ao Correlator.

    Args:
        components: Dicionário de componentes retornado por startup().
        interval:   Intervalo entre ciclos de correlação em segundos.
    """
    from engine.correlator import CorrelationSnapshot
    import time

    correlator = components["correlator"]
    icmp = components["icmp_collector"]
    dns = components["dns_collector"]
    snmp = components["snmp_collector"]
    event_bus = components["event_bus"]

    while True:
        await asyncio.sleep(interval)
        try:
            snapshot = CorrelationSnapshot()

            # Dados ICMP
            if icmp:
                results = icmp.last_results
                gw = results.get("gateway")
                inet = results.get("cloudflare") or results.get("google_dns")
                if gw:
                    snapshot.gateway_rtt_ms = gw.rtt_avg
                    snapshot.gateway_loss = gw.packet_loss
                    if not gw.is_reachable and "gateway" in icmp._outage_start:
                        snapshot.gateway_unreachable_since = icmp._outage_start["gateway"]
                if inet:
                    snapshot.internet_rtt_ms = inet.rtt_avg
                    snapshot.internet_loss = inet.packet_loss

            # Dados DNS
            if dns and dns.last_result:
                dns_result = dns.last_result
                interno = dns_result.resolvers.get("interno")
                externo = dns_result.get_external_fastest()
                if interno:
                    snapshot.dns_internal_ms = interno.avg_latency_ms
                if externo:
                    snapshot.dns_external_ms = externo.avg_latency_ms

            # Dados SNMP
            if snmp and snmp.last_result:
                r = snmp.last_result
                snapshot.cpu_usage = r.cpu_usage
                snapshot.cpu_high_since = snmp._cpu_high_since
                if r.wifi_radios:
                    radio = r.wifi_radios[0]
                    snapshot.channel_utilization = radio.get("channel_utilization")
                    snapshot.noise_floor = radio.get("noise_floor")
                    snapshot.retries_percent = radio.get("retries_percent")

            # Correlação
            alerts = correlator.analyze(snapshot)
            if alerts:
                for alert in alerts:
                    event_bus.publish_alert(alert)

            status = correlator.get_status()
            event_bus.publish_status(status, len(correlator.active_alerts))

        except Exception as exc:
            logger.error("Erro no loop de correlação: %s", exc)


# ─── Entry Point ──────────────────────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(description="Home Net Monitor")
    parser.add_argument("--host", default=None, help="Host de escuta (padrão: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=None, help="Porta (padrão: 8080)")
    parser.add_argument("--config", type=Path, default=Path("config.json"), help="Arquivo de configuração")
    parser.add_argument("--snmp-host", default=None, help="IP do Mikrotik para SNMP")
    parser.add_argument("--debug", action="store_true", help="Modo debug (log detalhado)")
    return parser.parse_args()


async def main_async():
    args = parse_args()
    config = load_config(args.config)

    if args.host:
        config["host"] = args.host
    if args.port:
        config["port"] = args.port
    if args.snmp_host:
        config["snmp_host"] = args.snmp_host
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        config["log_level"] = "DEBUG"

    components = await startup(config)

    # Adiciona loop de correlação
    corr_task = asyncio.create_task(
        run_collection_loop(components),
        name="correlator-loop"
    )
    components["tasks"].append(corr_task)

    app = create_app(config, components)

    import uvicorn
    uvicorn_config = uvicorn.Config(
        app,
        host=config["host"],
        port=config["port"],
        log_level=config["log_level"].lower(),
        access_log=False,
    )
    server = uvicorn.Server(uvicorn_config)

    logger.info("Dashboard disponível em http://%s:%s", config["host"], config["port"])
    logger.info("Documentação da API:    http://%s:%s/api/docs", config["host"], config["port"])

    try:
        await asyncio.gather(
            server.serve(),
            *components["tasks"],
        )
    except KeyboardInterrupt:
        logger.info("Encerrando Home Net Monitor...")
        server.should_exit = True
        for task in components["tasks"]:
            task.cancel()
        await components["db"].close()


if __name__ == "__main__":
    asyncio.run(main_async())
