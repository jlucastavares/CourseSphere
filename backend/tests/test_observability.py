"""
Testes da observabilidade: health check, métricas, request_id e logs
estruturados em JSON.
"""
import json
import logging

from conftest import auth
import observability


class TestHealthCheck:
    def test_health_responde_ok(self, client):
        r = client.get("/health")
        assert r.status_code == 200
        corpo = r.get_json()
        assert corpo["status"] == "ok"
        assert "instance" in corpo and "uptime_seconds" in corpo

    def test_health_fora_do_rate_limit(self, client):
        codigos = [client.get("/health").status_code for _ in range(250)]
        assert set(codigos) == {200}


class TestMetricas:
    def test_metrics_no_formato_prometheus(self, client):
        client.get("/chats", headers=auth("token-alice"))
        r = client.get("/metrics")
        assert r.status_code == 200
        texto = r.get_data(as_text=True)
        assert "http_requests_total" in texto
        assert "http_request_duration_seconds_bucket" in texto
        assert 'endpoint="/chats"' in texto

    def test_metrica_usa_padrao_da_rota_e_nao_o_id(self, client):
        client.delete("/chats/abc-123", headers=auth("token-alice"))
        texto = client.get("/metrics").get_data(as_text=True)
        assert 'endpoint="/chats/<chat_id>"' in texto
        assert "abc-123" not in texto

    def test_eventos_de_autenticacao_sao_contados(self, client):
        client.get("/chats", headers=auth("token-invalido"))
        texto = client.get("/metrics").get_data(as_text=True)
        assert 'auth_events_total{event="token_validation",result="invalid_token"}' in texto


class TestRastreabilidade:
    def test_toda_resposta_tem_request_id_e_instancia(self, client):
        r = client.get("/health")
        assert len(r.headers["X-Request-ID"]) >= 8
        assert r.headers["X-Instance"] == observability.INSTANCE

    def test_request_id_do_cliente_e_reaproveitado(self, client):
        r = client.get("/health", headers={"X-Request-ID": "teste-12345678"})
        assert r.headers["X-Request-ID"] == "teste-12345678"


class TestLogsEstruturados:
    def _registro(self, **fields):
        record = logging.LogRecord("coursesphere", logging.INFO, __file__, 1, "request", None, None)
        record.fields = fields
        return json.loads(observability.JsonFormatter().format(record))

    def test_log_e_json_valido_com_campos_padrao(self):
        log = self._registro(event="request", status=200)
        for campo in ("timestamp", "level", "message", "instance", "event", "status"):
            assert campo in log

    def test_log_de_requisicao_nao_contem_token(self, client, caplog):
        caplog.set_level(logging.INFO, logger="coursesphere")
        client.get("/users/info?id_token=token-alice")
        texto = " ".join(str(getattr(r, "fields", "")) for r in caplog.records)
        assert "token-alice" not in texto
