"""
Validação de entrada do backend.

Toda informação vinda do cliente é validada aqui antes de ser gravada no
Firebase: tipo, tamanho e valores permitidos. Campos desconhecidos são
descartados (allowlist), de modo que o cliente não consegue gravar
estruturas arbitrárias no banco.
"""
import re

# Limites de tamanho
MAX_REQUEST_BYTES = 256 * 1024       # corpo máximo de uma requisição (256 KB)
MAX_QUERY_CHARS = 1000               # pergunta enviada ao chatbot
MAX_ABOUT_CHARS = 2000               # campo "Tell me about yourself"
MAX_SHORT_TEXT = 120                 # college, nomes de major/minor/curso
MAX_LIST_ITEMS = {"majors": 10, "minors": 10, "courses": 150}
MAX_MESSAGES_PER_REQUEST = 50
MAX_MESSAGE_TEXT = 10000

YEAR_OPTIONS = {"freshman", "sophomore", "junior", "senior", "graduate"}
MESSAGE_SENDERS = {"user", "bot"}
# IDs de chat são UUIDs gerados pelo frontend; aceitamos apenas
# caracteres seguros para uso como chave no Realtime Database.
CHAT_ID_REGEX = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


class ValidationError(ValueError):
    """Erro de validação com mensagem segura para devolver ao cliente."""


def _optional_str(value, field, max_len):
    if value is None:
        return ""
    if not isinstance(value, str):
        raise ValidationError(f"'{field}' must be a string")
    value = value.strip()
    if len(value) > max_len:
        raise ValidationError(f"'{field}' must have at most {max_len} characters")
    return value


def _str_list(value, field):
    if value is None:
        return []
    if not isinstance(value, list):
        raise ValidationError(f"'{field}' must be a list")
    if len(value) > MAX_LIST_ITEMS[field]:
        raise ValidationError(f"'{field}' must have at most {MAX_LIST_ITEMS[field]} items")
    return [_optional_str(item, field, MAX_SHORT_TEXT) for item in value]


def validate_user_info(data: dict) -> dict:
    """Valida e normaliza o perfil enviado em POST /users/info."""
    year = _optional_str(data.get("year"), "year", MAX_SHORT_TEXT)
    if year and year not in YEAR_OPTIONS:
        raise ValidationError("'year' has an invalid value")
    return {
        "majors": _str_list(data.get("majors"), "majors"),
        "minors": _str_list(data.get("minors"), "minors"),
        "courses": _str_list(data.get("courses"), "courses"),
        "college": _optional_str(data.get("college"), "college", MAX_SHORT_TEXT),
        "year": year,
        "about": _optional_str(data.get("about"), "about", MAX_ABOUT_CHARS),
    }


def validate_query(value) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValidationError("Query is required")
    if len(value) > MAX_QUERY_CHARS:
        raise ValidationError(f"Query must have at most {MAX_QUERY_CHARS} characters")
    return value.strip()


def validate_chat_id(chat_id: str) -> str:
    if not CHAT_ID_REGEX.match(chat_id or ""):
        raise ValidationError("Invalid chat id")
    return chat_id


def _validate_content(content):
    # Mensagem do usuário: texto. Resposta do bot: objeto com
    # botResponse (texto) e newRecommendations (lista).
    if isinstance(content, str):
        if len(content) > MAX_MESSAGE_TEXT:
            raise ValidationError("Message content is too long")
        return content
    if isinstance(content, dict):
        bot_response = content.get("botResponse", "")
        recommendations = content.get("newRecommendations", [])
        if not isinstance(bot_response, str) or len(bot_response) > MAX_MESSAGE_TEXT:
            raise ValidationError("Invalid bot response")
        if not isinstance(recommendations, list):
            raise ValidationError("Invalid recommendations")
        return {"botResponse": bot_response, "newRecommendations": recommendations}
    raise ValidationError("Invalid message content")


def validate_messages(messages) -> list:
    """Valida a lista de mensagens de POST /chats/<id>/messages."""
    if not isinstance(messages, list) or not messages:
        raise ValidationError("'messages' must be a non-empty list")
    if len(messages) > MAX_MESSAGES_PER_REQUEST:
        raise ValidationError(f"At most {MAX_MESSAGES_PER_REQUEST} messages per request")
    cleaned = []
    for message in messages:
        if not isinstance(message, dict):
            raise ValidationError("Each message must be an object")
        if message.get("sender") not in MESSAGE_SENDERS:
            raise ValidationError("Invalid message sender")
        message_id = message.get("messageID")
        if message_id is not None and (not isinstance(message_id, str) or len(message_id) > 200):
            raise ValidationError("Invalid messageID")
        cleaned.append({
            "sender": message["sender"],
            "content": _validate_content(message.get("content")),
            "messageID": message_id,
            "timestamp": _optional_str(message.get("timestamp"), "timestamp", 64),
        })
    return cleaned
