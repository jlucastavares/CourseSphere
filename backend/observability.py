"""
Observabilidade do backend: logs estruturados em JSON e métricas
no formato do Prometheus.

- Cada log é uma linha JSON (timestamp, nível, evento, instância,
  request_id...), fácil de buscar e filtrar em ferramentas como Loki,
  Elasticsearch ou CloudWatch.
- Cada requisição recebe um request_id, devolvido no header X-Request-ID,
  para que um erro visto pelo usuário possa ser encontrado nos logs.
- Métricas de requisições, latência e eventos de autenticação ficam
  expostas em /metrics para o Prometheus coletar.

Dados sensíveis (tokens, senhas, e-mails, corpo das requisições) nunca
são registrados. O usuário aparece apenas pelo uid.
"""
import json
import logging
import os
import re
import socket
import time
import uuid
from datetime import datetime, timezone

from flask import g, has_request_context, request
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest

# Nome da instância (no Docker, o hostname é o ID do container). Usado nos
# logs e no header X-Instance para mostrar qual réplica atendeu a requisição.
INSTANCE = os.environ.get("INSTANCE_NAME") or socket.gethostname()
START_TIME = time.time()
REQUEST_ID_REGEX = re.compile(r"^[A-Za-z0-9-]{8,64}$")

# Métricas (Prometheus)

REQUEST_COUNT = Counter(
    "http_requests_total",
    "Total de requisições HTTP",
    ["method", "endpoint", "status"],
)
REQUEST_LATENCY = Histogram(
    "http_request_duration_seconds",
    "Latência das requisições HTTP (segundos)",
    ["method", "endpoint"],
    buckets=(0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 0.8, 1, 2.5, 5),
)
AUTH_EVENTS = Counter(
    "auth_events_total",
    "Eventos de autenticação",
    ["event", "result"],
)



# Logs estruturados (JSON)

class JsonFormatter(logging.Formatter):
    def format(self, record):
        entry = {
            "timestamp": datetime.fromtimestamp(record.created, timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "instance": INSTANCE,
        }
        if has_request_context() and "request_id" in g:
            entry["request_id"] = g.request_id
        fields = getattr(record, "fields", None)
        if isinstance(fields, dict):
            entry.update(fields)
        if record.exc_info:
            entry["exception"] = self.formatException(record.exc_info)
        return json.dumps(entry, ensure_ascii=False, default=str)


def configure_logging(level=logging.INFO):
    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(level)
    # O log de acesso padrão do servidor de desenvolvimento é substituído
    # pelo log "request" abaixo (estruturado e sem query string).
    logging.getLogger("werkzeug").setLevel(logging.WARNING)


def log_event(logger, event, level=logging.INFO, **fields):
    """Registra um evento de negócio/segurança como log estruturado."""
    logger.log(level, event, extra={"fields": {"event": event, **fields}})


def record_auth_event(logger, event, result, level=logging.INFO, **fields):
    """Conta o evento em auth_events_total e registra no log."""
    AUTH_EVENTS.labels(event=event, result=result).inc()
    log_event(logger, f"auth.{event}", level=level, result=result, **fields)


# Integração com o Flask

def init_app(app, logger, limiter=None):
    @app.before_request
    def start_request():
        incoming = request.headers.get("X-Request-ID", "")
        g.request_id = incoming if REQUEST_ID_REGEX.match(incoming) else uuid.uuid4().hex
        g.start_time = time.perf_counter()

    @app.after_request
    def finish_request(response):
        duration = time.perf_counter() - g.get("start_time", time.perf_counter())
        # Usa o padrão da rota (ex.: /chats/<chat_id>) e não a URL real,
        # para não criar uma série de métrica por ID.
        endpoint = request.url_rule.rule if request.url_rule else "unmatched"

        if endpoint != "/metrics":
            REQUEST_COUNT.labels(request.method, endpoint, str(response.status_code)).inc()
            REQUEST_LATENCY.labels(request.method, endpoint).observe(duration)

        if endpoint not in ("/metrics", "/health"):
            status = response.status_code
            level = logging.ERROR if status >= 500 else logging.WARNING if status >= 400 else logging.INFO
            log_event(
                logger, "request", level=level,
                method=request.method,
                path=request.path,          # sem query string
                endpoint=endpoint,
                status=status,
                duration_ms=round(duration * 1000, 2),
                client_ip=request.remote_addr,
                uid=g.get("uid"),
            )

        response.headers["X-Request-ID"] = g.get("request_id", "")
        response.headers["X-Instance"] = INSTANCE
        return response

    def health():
        # Liveness: o processo está de pé e respondendo.
        return {
            "status": "ok",
            "instance": INSTANCE,
            "uptime_seconds": round(time.time() - START_TIME, 1),
        }, 200

    def metrics():
        return generate_latest(), 200, {"Content-Type": CONTENT_TYPE_LATEST}

    app.add_url_rule("/health", "health", health, methods=["GET"])
    app.add_url_rule("/metrics", "metrics", metrics, methods=["GET"])

    # Health check e coleta de métricas não entram no rate limit.
    if limiter is not None:
        limiter.exempt(health)
        limiter.exempt(metrics)
