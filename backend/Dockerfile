# Imagem do backend (Flask) para produção
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Usuário sem privilégios: o processo não roda como root.
RUN useradd --create-home --uid 10001 appuser

# Dependências primeiro, para aproveitar o cache de camadas do Docker.
COPY requirements.txt .
RUN pip install -r requirements.txt gunicorn

# Apenas o código necessário. Segredos (credentials.json, config.json)
# ficam de fora pelo .dockerignore e são montados em tempo de execução.
COPY endpoints.py firebase.py main.py query_manager.py observability.py validation.py query_types.json ./

USER appuser
EXPOSE 5000

# Gunicorn (servidor WSGI de produção) no lugar do servidor de
# desenvolvimento do Flask. 1 processo com 4 threads por container:
# a escala horizontal é feita com mais containers atrás do Nginx, e um
# único processo mantém as métricas do /metrics consistentes.
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "1", "--threads", "4", "--timeout", "30", "endpoints:app"]
