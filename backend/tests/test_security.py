"""
Testes automatizados de segurança do CourseSphere.

Cada teste reproduz um cenário de ataque encontrado na análise (Seção 1)
e comprova que a correção ou o hardening (Seções 2 e 3) o bloqueia.
Também há testes de regressão, que garantem que o uso normal da
aplicação continua funcionando.

Como rodar (na pasta backend):
    pip install -r requirements-dev.txt
    python -m pytest -v
"""
import runpy

import flask

import endpoints
from conftest import EXISTING_EMAIL, auth

PERFIL_VALIDO = {
    "majors": ["Computer Science"],
    "minors": [],
    "year": "junior",
    "college": "College of Engineering",
    "courses": ["CS 2110", "CS 3110"],
    "about": "Tenho interesse em IA.",
}
CHAT_ID = "3f6c1a2e-1b2c-4d5e-8f90-123456789abc"
MENSAGENS = [
    {"sender": "user", "content": "Oi", "messageID": "m1", "timestamp": "2026-10-27T10:00:00Z"},
    {"sender": "bot", "content": {"botResponse": "Olá!", "newRecommendations": []},
     "messageID": "m2", "timestamp": "2026-10-27T10:00:01Z"},
]


# ---------------------------------------------------------------------------
# Regressão: o uso normal continua funcionando
# ---------------------------------------------------------------------------

class TestRegressao:
    def test_salvar_e_carregar_perfil(self, client):
        r = client.post("/users/info", json=PERFIL_VALIDO, headers=auth("token-alice"))
        assert r.status_code == 200
        r = client.get("/users/info", headers=auth("token-alice"))
        assert r.status_code == 200
        assert r.get_json()["courses"] == ["CS 2110", "CS 3110"]

    def test_salvar_listar_e_apagar_chat(self, client):
        r = client.post(f"/chats/{CHAT_ID}/messages", json={"messages": MENSAGENS},
                        headers=auth("token-alice"))
        assert r.status_code == 200
        r = client.get("/chats", headers=auth("token-alice"))
        assert [c["id"] for c in r.get_json()["chats"]] == [CHAT_ID]
        r = client.delete(f"/chats/{CHAT_ID}", headers=auth("token-alice"))
        assert r.status_code == 200

    def test_consulta_anonima_e_autenticada(self, client):
        assert client.post("/users/query", json={"query": "CS 2110?"}).status_code == 200
        assert client.post("/users/query", json={"query": "CS 2110?"},
                           headers=auth("token-alice")).status_code == 200

    def test_cadastro_valido(self, client):
        r = client.post("/users/create", json={"email": "novo@exemplo.com", "password": "Senha@123"})
        assert r.status_code == 200


# ---------------------------------------------------------------------------
# Controle de acesso: um usuário não acessa dados de outro
# ---------------------------------------------------------------------------

class TestControleDeAcesso:
    def test_usuario_nao_le_perfil_de_outro(self, client):
        client.post("/users/info", json=PERFIL_VALIDO, headers=auth("token-alice"))
        r = client.get("/users/info", headers=auth("token-bob"))
        assert r.status_code == 200
        assert r.get_json() is None  # bob só enxerga o próprio perfil (vazio)

    def test_usuario_nao_lista_chats_de_outro(self, client):
        client.post(f"/chats/{CHAT_ID}/messages", json={"messages": MENSAGENS},
                    headers=auth("token-alice"))
        r = client.get("/chats", headers=auth("token-bob"))
        assert r.get_json()["chats"] == []

    def test_usuario_nao_apaga_chat_de_outro(self, client, fake_db):
        client.post(f"/chats/{CHAT_ID}/messages", json={"messages": MENSAGENS},
                    headers=auth("token-alice"))
        client.delete(f"/chats/{CHAT_ID}", headers=auth("token-bob"))
        assert CHAT_ID in fake_db.chats["alice"]  # o chat da alice continua lá


# ---------------------------------------------------------------------------
# VULN-02: modo debug
# ---------------------------------------------------------------------------

def _executar_servidor(monkeypatch):
    """Executa endpoints.py como script, capturando os argumentos de app.run()."""
    chamada = {}
    monkeypatch.setattr(flask.Flask, "run", lambda self, **kwargs: chamada.update(kwargs))
    runpy.run_path(endpoints.__file__, run_name="__main__")
    return chamada


class TestModoDebug:
    def test_debug_desligado_por_padrao(self, monkeypatch):
        monkeypatch.delenv("FLASK_DEBUG", raising=False)
        assert _executar_servidor(monkeypatch)["debug"] is False

    def test_debug_so_liga_quando_pedido_explicitamente(self, monkeypatch):
        monkeypatch.setenv("FLASK_DEBUG", "1")
        assert _executar_servidor(monkeypatch)["debug"] is True

    def test_console_do_werkzeug_indisponivel(self, client):
        assert client.get("/console").status_code == 404


# ---------------------------------------------------------------------------
# VULN-03: mensagens de erro e enumeração de usuários
# ---------------------------------------------------------------------------

class TestMensagensDeErro:
    def test_cadastro_nao_revela_email_existente(self, client):
        existente = client.post("/users/create",
                                json={"email": EXISTING_EMAIL, "password": "Senha@123"})
        assert existente.status_code == 400
        assert "EMAIL_EXISTS" not in existente.get_data(as_text=True)
        assert "already exists" not in existente.get_data(as_text=True)

    def test_corpo_nulo_nao_gera_erro_interno(self, client):
        r = client.post("/users/create", data="null", content_type="application/json")
        assert r.status_code == 400
        assert r.get_json() == {"error": "Invalid JSON body"}

    def test_falha_interna_nao_vaza_detalhe(self, client, fake_db):
        fake_db.fail_next = True
        r = client.get("/chats", headers=auth("token-alice"))
        assert r.status_code == 500
        assert "segredo interno" not in r.get_data(as_text=True)
        assert "RTDB" not in r.get_data(as_text=True)

    def test_token_invalido_nao_vaza_detalhe(self, client):
        r = client.get("/users/info", headers=auth("abc"))
        assert r.status_code == 401
        assert "segments" not in r.get_data(as_text=True)

    def test_rota_inexistente_responde_json(self, client):
        r = client.get("/nao-existe")
        assert r.status_code == 404
        assert r.is_json


# ---------------------------------------------------------------------------
# VULN-05 / VULN-08: token de sessão
# ---------------------------------------------------------------------------

class TestTokenDeSessao:
    def test_token_na_url_e_recusado(self, client):
        assert client.get("/users/info?id_token=token-alice").status_code == 401

    def test_token_no_corpo_e_recusado(self, client):
        r = client.post("/users/info", json={**PERFIL_VALIDO, "id_token": "token-alice"})
        assert r.status_code == 401

    def test_requisicao_sem_token_retorna_401(self, client):
        assert client.get("/chats").status_code == 401

    def test_logout_revoga_o_token(self, client):
        assert client.get("/chats", headers=auth("token-alice")).status_code == 200
        assert client.post("/auth/logout", headers=auth("token-alice")).status_code == 200
        assert client.get("/chats", headers=auth("token-alice")).status_code == 401

    def test_logout_nao_afeta_outro_usuario(self, client):
        client.post("/auth/logout", headers=auth("token-alice"))
        assert client.get("/chats", headers=auth("token-bob")).status_code == 200


# ---------------------------------------------------------------------------
# VULN-04: rate limiting
# ---------------------------------------------------------------------------

class TestRateLimiting:
    def test_cadastro_bloqueado_apos_5_tentativas_por_minuto(self, client):
        codigos = [
            client.post("/users/create",
                        json={"email": f"bot{i}@exemplo.com", "password": "123456"}).status_code
            for i in range(7)
        ]
        assert codigos == [200] * 5 + [429] * 2

    def test_resposta_429_informa_tempo_de_espera(self, client):
        for i in range(6):
            r = client.post("/users/create",
                            json={"email": f"bot{i}@exemplo.com", "password": "123456"})
        assert r.status_code == 429
        assert "Retry-After" in r.headers

    def test_consulta_bloqueada_apos_20_por_minuto(self, client):
        codigos = [client.post("/users/query", json={"query": "x"}).status_code
                   for _ in range(22)]
        assert codigos.count(429) == 2


# ---------------------------------------------------------------------------
# VULN-07: headers de segurança e CORS
# ---------------------------------------------------------------------------

class TestHeadersECors:
    def test_headers_de_seguranca_presentes(self, client):
        r = client.get("/users/info", headers=auth("token-alice"))
        assert r.headers["X-Content-Type-Options"] == "nosniff"
        assert r.headers["X-Frame-Options"] == "DENY"
        assert "default-src 'none'" in r.headers["Content-Security-Policy"]
        assert r.headers["Referrer-Policy"] == "no-referrer"
        assert "max-age" in r.headers["Strict-Transport-Security"]
        assert r.headers["Cache-Control"] == "no-store"

    def test_cors_recusa_origem_desconhecida(self, client):
        r = client.options("/chats", headers={
            "Origin": "https://atacante.example",
            "Access-Control-Request-Method": "DELETE",
        })
        assert "Access-Control-Allow-Origin" not in r.headers

    def test_cors_permite_o_frontend(self, client):
        r = client.options("/chats", headers={
            "Origin": "http://localhost:5173",
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "authorization",
        })
        assert r.headers["Access-Control-Allow-Origin"] == "http://localhost:5173"


# ---------------------------------------------------------------------------
# VULN-06: validação de entrada
# ---------------------------------------------------------------------------

class TestValidacaoDeEntrada:
    def test_ano_fora_da_lista_e_recusado(self, client):
        r = client.post("/users/info", json={**PERFIL_VALIDO, "year": "hacker"},
                        headers=auth("token-alice"))
        assert r.status_code == 400

    def test_texto_muito_longo_e_recusado(self, client):
        r = client.post("/users/info", json={**PERFIL_VALIDO, "about": "A" * 5000},
                        headers=auth("token-alice"))
        assert r.status_code == 400

    def test_campos_desconhecidos_sao_descartados(self, client, fake_db):
        client.post("/users/info", json={**PERFIL_VALIDO, "isAdmin": True},
                    headers=auth("token-alice"))
        assert "isAdmin" not in fake_db.users["alice"]

    def test_remetente_forjado_e_recusado(self, client):
        r = client.post(f"/chats/{CHAT_ID}/messages",
                        json={"messages": [{"sender": "admin", "content": "x"}]},
                        headers=auth("token-alice"))
        assert r.status_code == 400

    def test_excesso_de_mensagens_e_recusado(self, client):
        r = client.post(f"/chats/{CHAT_ID}/messages",
                        json={"messages": [MENSAGENS[0]] * 500},
                        headers=auth("token-alice"))
        assert r.status_code == 400

    def test_chat_id_invalido_e_recusado(self, client):
        r = client.delete("/chats/a.b$c", headers=auth("token-alice"))
        assert r.status_code == 400

    def test_corpo_acima_do_limite_retorna_413(self, client):
        corpo = '{"about": "' + "A" * 1_000_000 + '"}'
        r = client.post("/users/info", data=corpo, content_type="application/json",
                        headers=auth("token-alice"))
        assert r.status_code == 413
