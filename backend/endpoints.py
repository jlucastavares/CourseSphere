import os
from functools import wraps
from flask import Flask, request, jsonify, g
from flask_cors import CORS
from query_manager import QueryManager
from firebase import Firebase
from main import hashFunction

app = Flask(__name__)
CORS(app)

# TODO: figure out the blueprint thing below
#app.register_blueprint(courses_bp)

success_response = lambda data, code: (jsonify(data), code)
error_response = lambda error, code: (jsonify({'error': error}), code)


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
def create_user():
    data = request.get_json()
    email = data.get("email")
    password = data.get("password")
    if not email:
        return error_response("Email is required", 400)
    if not password:
        return error_response("Password is required", 400)
    try:
        return success_response(Firebase.create_user(email, password), 200)
    except Exception as e:
        return error_response(f"Error creating user: {str(e)}", 400)

@app.route("/users/info", methods=["POST"])
@require_auth
def set_user_info():
    data = request.get_json()
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
    except Exception as e:
        return error_response(f"Error with setting user info: {str(e)}", 400)
        
@app.route("/users/info", methods=["GET"])
@require_auth
def get_user_info():
    try:
        user_info = Firebase.get_user_info(g.uid)
        return success_response(user_info, 200)
    except Exception as e:
        return error_response(f"Error getting user info: {str(e)}", 400)
  
@app.route("/users/query", methods=["POST"])
def get_user_query():
    try:
        body = request.get_json() or {}
        query = body.get("query")
        # Autenticação opcional: se houver token, ele vem apenas do header.
        id_token = get_bearer_token()
        user_info = Firebase.try_get_user_info(id_token) if id_token else None
        return success_response(QueryManager(query, user_info).response, 200)
    except Exception as e:
        return error_response(f"Error getting generating query: {str(e)}", 400)

@app.route('/hash', methods=['POST'])
@require_auth
def generate_message_id():
    try:
        data = request.get_json()  
        message_id = hashFunction(data)
        return jsonify({'messageID': message_id}), 200  
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route("/chats", methods=["GET"])
@require_auth
def list_chats():
    try:
        user_id = g.uid
        return success_response({"chats": Firebase.get_chats(user_id)}, 200)
    except Exception as e:
        return error_response(f"Error getting chats: {str(e)}", 400)

@app.route("/chats/<chat_id>/messages", methods=["POST"])
@require_auth
def save_chat(chat_id):
    try:
        user_id = g.uid
        messages = request.get_json().get('messages', [])
        Firebase.save_chat(user_id, chat_id, messages)
        return jsonify({'message': 'Messages saved successfully'}), 200
    except Exception as e:
        return jsonify({'error': f"Error saving messages: {str(e)}"}), 400

@app.route("/chats/<chat_id>", methods=["DELETE"])
@require_auth
def delete_chat(chat_id):
    try:
        user_id = g.uid
        Firebase.delete_chat(user_id, chat_id)
        return success_response({'message': 'Message deleted successfully'}, 200)
    except Exception as e:
        return error_response(f"Error deleting message: {str(e)}", 400)


if __name__ == '__main__':
    # O modo debug do Flask ativa o Werkzeug Debugger (traceback + console
    # Python no navegador). Ele nunca deve ficar fixo no código: só é ligado
    # quando o desenvolvedor pede explicitamente com FLASK_DEBUG=1.
    debug_mode = os.environ.get("FLASK_DEBUG", "0") == "1"
    host = os.environ.get("FLASK_RUN_HOST", "127.0.0.1")
    port = int(os.environ.get("FLASK_RUN_PORT", "5000"))
    app.run(host=host, port=port, debug=debug_mode)
