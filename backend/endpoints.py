import os
import re
import logging
from functools import wraps
from flask import Flask, request, jsonify, g
from werkzeug.exceptions import HTTPException
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from query_manager import QueryManager
from firebase import Firebase
from main import hashFunction

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger("coursesphere")

app = Flask(__name__)

# CORS restrito: apenas as origens do frontend podem chamar a API pelo
# navegador. A lista vem da variável CORS_ORIGINS (separada por vírgula);
# o padrão cobre o Vite em desenvolvimento (5173) e o container (3000).
DEFAULT_CORS_ORIGINS = (
    "http://localhost:5173,http://127.0.0.1:5173,"
    "http://localhost:3000,http://127.0.0.1:3000"
)
CORS_ORIGINS = [
    o.strip() for o in os.environ.get("CORS_ORIGINS", DEFAULT_CORS_ORIGINS).split(",")
    if o.strip()
]
CORS(
    app,
    origins=CORS_ORIGINS,
    methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
    max_age=600,
)

# Rate limiting por endereço IP. Limites padrão para todas as rotas e
# limites mais rígidos nas rotas sensíveis (cadastro e consulta ao LLM).
# Em produção com várias instâncias, use um storage compartilhado
# (ex.: RATELIMIT_STORAGE_URI=redis://redis:6379) para que o limite
# valha para o conjunto e não para cada instância separadamente.
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per minute"],
    storage_uri=os.environ.get("RATELIMIT_STORAGE_URI", "memory://"),
    headers_enabled=True,  # envia X-RateLimit-* e Retry-After ao cliente
)

# TODO: figure out the blueprint thing below
#app.register_blueprint(courses_bp)

@app.after_request
def set_security_headers(response):
    """
    Headers de segurança HTTP aplicados a todas as respostas da API.
    """
    # Impede o navegador de "adivinhar" o tipo do conteúdo (MIME sniffing).
    response.headers["X-Content-Type-Options"] = "nosniff"
    # Impede que a resposta seja exibida dentro de um <iframe> (clickjacking).
    response.headers["X-Frame-Options"] = "DENY"
    # A API só devolve JSON: nenhum script, estilo ou frame é permitido.
    response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
    # Não vaza a URL de origem para outros sites.
    response.headers["Referrer-Policy"] = "no-referrer"
    # Força HTTPS por 1 ano quando a API estiver atrás de TLS
    # (navegadores ignoram este header em conexões HTTP).
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    # Respostas com dados do usuário não devem ficar em cache.
    response.headers["Cache-Control"] = "no-store"
    return response


success_response = lambda data, code: (jsonify(data), code)
error_response = lambda error, code: (jsonify({'error': error}), code)

# Mensagens devolvidas ao cliente são sempre genéricas. O detalhe técnico
# da exceção fica apenas no log do servidor (logger.exception), nunca na
# resposta HTTP.
GENERIC_SERVER_ERROR = "Internal server error"
SIGNUP_FAILED = "Could not create account. Check your data or try logging in."
EMAIL_REGEX = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


@app.errorhandler(HTTPException)
def handle_http_exception(e):
    # Erros HTTP conhecidos (404, 405, 415...) em JSON, sem página HTML.
    return error_response(e.name, e.code)


@app.errorhandler(Exception)
def handle_unexpected_exception(e):
    # Rede de segurança: qualquer exceção não tratada é registrada no log
    # com traceback e o cliente recebe apenas uma mensagem genérica.
    logger.exception("Unhandled exception on %s %s", request.method, request.path)
    return error_response(GENERIC_SERVER_ERROR, 500)


def get_json_body():
    """Retorna o corpo JSON como dict, ou None se ausente/inválido."""
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else None


def get_bearer_token():
    """
    Extrai o ID token do header 'Authorization: Bearer <token>'.

    O token é uma credencial de sessão: ele nunca deve trafegar na URL
    (query string) nem no corpo da requisição, pois URLs são gravadas em
    logs de servidor/proxy e no histórico do navegador.
    """
    auth_header = request.headers.get("Authorization", "")
    scheme, _, token = auth_header.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        return None
    return token.strip()


def require_auth(view):
    """
    Decorator que exige um ID token válido no header Authorization e
    disponibiliza o uid autenticado em g.uid.
    """
    @wraps(view)
    def wrapper(*args, **kwargs):
        id_token = get_bearer_token()
        if not id_token:
            return error_response("Authentication required", 401)
        try:
            g.uid = Firebase.verify_id_token(id_token).get('uid')
        except Exception:
            return error_response("Invalid or expired token", 401)
        return view(*args, **kwargs)
    return wrapper

@app.route("/users/create", methods=["POST"])
@limiter.limit("5 per minute; 20 per hour")
def create_user():
    data = get_json_body()
    if data is None:
        return error_response("Invalid JSON body", 400)
    email = data.get("email")
    password = data.get("password")
    # Validações feitas localmente: dão feedback útil ao usuário sem
    # depender (nem expor) a mensagem de erro do Firebase.
    if not isinstance(email, str) or not EMAIL_REGEX.match(email):
        return error_response("A valid email is required", 400)
    if not isinstance(password, str) or len(password) < 6:
        return error_response("Password must have at least 6 characters", 400)
    try:
        return success_response(Firebase.create_user(email, password), 200)
    except Exception:
        # A mensagem do Firebase revelaria se o e-mail já está cadastrado
        # (EMAIL_EXISTS), permitindo enumerar usuários. Resposta única para
        # qualquer falha; o motivo real vai apenas para o log.
        logger.exception("User creation failed")
        return error_response(SIGNUP_FAILED, 400)

@app.route("/users/info", methods=["POST"])
@require_auth
def set_user_info():
    data = get_json_body()
    if data is None:
        return error_response("Invalid JSON body", 400)
    try:
        uid = g.uid
        majors = data.get("majors")
        minors = data.get("minors")
        year = data.get("year")
        college = data.get("college")
        courses = data.get("courses")
        about = data.get("about")
        user_info = {
            "majors": majors,
            "minors": minors,
            "courses": courses,
            "college": college,
            "year": year,
            "about": about
        }
        Firebase.set_user_info(uid, user_info) 
        return success_response({"message": "User info set successfully", "uid": uid}, 200)
    except Exception:
        logger.exception("Failed to set user info (uid=%s)", g.uid)
        return error_response("Could not save user info", 500)
        
@app.route("/users/info", methods=["GET"])
@require_auth
def get_user_info():
    try:
        user_info = Firebase.get_user_info(g.uid)
        return success_response(user_info, 200)
    except Exception:
        logger.exception("Failed to get user info (uid=%s)", g.uid)
        return error_response("Could not load user info", 500)
  
@app.route("/users/query", methods=["POST"])
@limiter.limit("20 per minute")
def get_user_query():
    try:
        body = get_json_body() or {}
        query = body.get("query")
        if not isinstance(query, str) or not query.strip():
            return error_response("Query is required", 400)
        # Autenticação opcional: se houver token, ele vem apenas do header.
        id_token = get_bearer_token()
        user_info = Firebase.try_get_user_info(id_token) if id_token else None
        return success_response(QueryManager(query, user_info).response, 200)
    except Exception:
        logger.exception("Failed to process query")
        return error_response("Could not process query", 500)

@app.route('/hash', methods=['POST'])
@require_auth
def generate_message_id():
    try:
        data = request.get_json()  
        message_id = hashFunction(data)
        return jsonify({'messageID': message_id}), 200
    except Exception:
        logger.exception("Failed to generate message id")
        return error_response(GENERIC_SERVER_ERROR, 500)

@app.route("/chats", methods=["GET"])
@require_auth
def list_chats():
    try:
        user_id = g.uid
        return success_response({"chats": Firebase.get_chats(user_id)}, 200)
    except Exception:
        logger.exception("Failed to list chats (uid=%s)", g.uid)
        return error_response("Could not load chats", 500)

@app.route("/chats/<chat_id>/messages", methods=["POST"])
@require_auth
def save_chat(chat_id):
    try:
        user_id = g.uid
        data = get_json_body()
        if data is None:
            return error_response("Invalid JSON body", 400)
        messages = data.get('messages', [])
        if not isinstance(messages, list) or not all(isinstance(m, dict) for m in messages):
            return error_response("'messages' must be a list of objects", 400)
        Firebase.save_chat(user_id, chat_id, messages)
        return jsonify({'message': 'Messages saved successfully'}), 200
    except Exception:
        logger.exception("Failed to save chat (uid=%s)", g.uid)
        return error_response("Could not save messages", 500)

@app.route("/chats/<chat_id>", methods=["DELETE"])
@require_auth
def delete_chat(chat_id):
    try:
        user_id = g.uid
        Firebase.delete_chat(user_id, chat_id)
        return success_response({'message': 'Message deleted successfully'}, 200)
    except Exception:
        logger.exception("Failed to delete chat (uid=%s)", g.uid)
        return error_response("Could not delete chat", 500)


if __name__ == '__main__':
    # O modo debug do Flask ativa o Werkzeug Debugger (traceback + console
    # Python no navegador). Ele nunca deve ficar fixo no código: só é ligado
    # quando o desenvolvedor pede explicitamente com FLASK_DEBUG=1.
    debug_mode = os.environ.get("FLASK_DEBUG", "0") == "1"
    host = os.environ.get("FLASK_RUN_HOST", "127.0.0.1")
    port = int(os.environ.get("FLASK_RUN_PORT", "5000"))
    app.run(host=host, port=port, debug=debug_mode)
