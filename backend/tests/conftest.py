"""
Configuração dos testes automatizados de segurança do backend.

Os testes não acessam o Firebase real: o módulo `firebase` é substituído
por um dublê em memória (FakeFirebase) ANTES de importar a aplicação.
Assim os testes rodam em qualquer máquina ou no CI, sem credenciais e
sem criar contas reais.
"""
import os
import sys
import types

import pytest

BACKEND_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, BACKEND_DIR)

# Tokens de teste -> uid
TOKENS = {"token-alice": "alice", "token-bob": "bob"}
EXISTING_EMAIL = "existente@exemplo.com"


class FakeFirebase:
    """Dublê do Firebase com armazenamento em memória."""
    users = {}         # uid -> perfil
    chats = {}         # uid -> {chat_id: [mensagens]}
    revoked = set()    # uids com sessões revogadas
    fail_next = False  # simula uma falha interna do banco

    @classmethod
    def reset(cls):
        cls.users, cls.chats, cls.revoked, cls.fail_next = {}, {}, set(), False

    @classmethod
    def _maybe_fail(cls):
        if cls.fail_next:
            cls.fail_next = False
            raise Exception("RTDB internal error at users/alice/chats: segredo interno")

    @staticmethod
    def create_user(email, password):
        if email == EXISTING_EMAIL:
            raise Exception("Error creating user: The user with the provided email "
                            "already exists (EMAIL_EXISTS).")
        return {"message": "User created successfully", "user_id": "novo", "email": email}

    @staticmethod
    def verify_id_token(id_token):
        uid = TOKENS.get(id_token)
        if uid is None:
            raise Exception("Error verifying ID token: Wrong number of segments in token")
        if uid in FakeFirebase.revoked:
            raise Exception("Error verifying ID token: The Firebase ID token has been revoked.")
        return {"uid": uid}

    @staticmethod
    def revoke_sessions(uid):
        FakeFirebase.revoked.add(uid)

    @staticmethod
    def get_user_info(uid):
        FakeFirebase._maybe_fail()
        return FakeFirebase.users.get(uid)

    @staticmethod
    def set_user_info(uid, info):
        FakeFirebase.users[uid] = info

    @staticmethod
    def try_get_user_info(id_token):
        try:
            return FakeFirebase.get_user_info(FakeFirebase.verify_id_token(id_token)["uid"])
        except Exception:
            return None

    @staticmethod
    def get_chats(uid):
        FakeFirebase._maybe_fail()
        return [{"id": cid, "title": "Chat", "timestamp": ""}
                for cid in FakeFirebase.chats.get(uid, {})]

    @staticmethod
    def save_chat(uid, chat_id, messages):
        FakeFirebase.chats.setdefault(uid, {}).setdefault(chat_id, []).extend(messages)

    @staticmethod
    def delete_chat(uid, chat_id):
        FakeFirebase.chats.get(uid, {}).pop(chat_id, None)


# Substitui o módulo real antes de importar a aplicação.
fake_module = types.ModuleType("firebase")
fake_module.Firebase = FakeFirebase
sys.modules["firebase"] = fake_module

import endpoints  # noqa: E402  (precisa vir depois do dublê)


@pytest.fixture
def client():
    FakeFirebase.reset()
    if hasattr(endpoints, "limiter"):
        endpoints.limiter.reset()  # zera os contadores de rate limit entre testes
    endpoints.app.config["TESTING"] = True
    return endpoints.app.test_client()


@pytest.fixture
def fake_db():
    return FakeFirebase


def auth(token):
    return {"Authorization": f"Bearer {token}"}
