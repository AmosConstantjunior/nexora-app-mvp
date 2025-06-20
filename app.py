from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from firebase_admin import credentials, auth, storage, initialize_app
import os, json, re, base64
from functools import wraps

from fonctions.llm_service import summarize_text, translate_text, correct_text, generate_text, generate_chat_response
from fonctions.ocr_service import extract_text_from_file
from dotenv import load_dotenv

# -- App Setup --
app = Flask(__name__)
CORS(app, supports_credentials=True, resources={r"/ai/*": {"origins": "*"}})

load_dotenv()


# -- Firebase Init from ENV --
try:
    firebase_creds_json = os.getenv("FIREBASE_CREDENTIAL")

    if not firebase_creds_json:
        raise EnvironmentError("La variable d'environnement FIREBASE_CREDENTIAL est absente.")
    
    decoded_json = base64.b64decode(firebase_creds_json).decode("utf-8")
    firebase_creds = json.loads(decoded_json)

    cred = credentials.Certificate(firebase_creds)
    initialize_app(cred)

except Exception as e:
    raise RuntimeError(f"Erreur Firebase : {str(e)}")

# -- Professions et Tâches --
TACHES_PAR_PROFESSION = {
    'content_creator': ['Rédiger des articles', 'Corriger du texte', 'Traduire du contenu'],
    'developer': ['Générer du code', 'Corriger du code', 'Documenter du code'],
    'marketing': ['Créer des campagnes', 'Analyser des données', 'Gérer des réseaux sociaux'],
    'project_manager': ['Planifier un projet', 'Suivre les tâches', 'Faire des rapports'],
    'designer': ['Créer des maquettes', 'Optimiser UX', 'Analyser des retours utilisateurs'],
    'hr': ['Rédiger des offres', 'Filtrer les CVs', 'Planifier des entretiens'],
    'student': ['Prendre des notes', 'Faire des résumés', 'Organiser des tâches'],
    'other': ['Tâche personnalisée 1', 'Tâche personnalisée 2'],
}

# -- ACL --
ALLOWED_FUNCTIONS_BY_PROFESSION = {
    'content_creator': ["summarize", "translate", "correct"],
    'developer': ["summarize", "translate", "correct", "generate"],
    'marketing': ["summarize", "translate", "correct"],
    'project_manager': ["summarize", "translate", "correct"],
    'designer': ["summarize", "translate", "correct"],
    'hr': ["summarize", "translate", "correct"],
    'student': ["summarize", "translate"],
    'other': ["summarize", "translate"],
}

# -- Token Checker --
def firebase_token_required(function_slug):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            token = request.headers.get("Authorization")
            if not token or not token.startswith("Bearer "):
                return jsonify({"error": "Token manquant ou mal formaté"}), 401
            try:
                id_token = token.split(" ")[1]
                decoded_token = auth.verify_id_token(id_token)

                # Récupération de la profession de l'utilisateur
                profession = decoded_token.get('profession')
                if not profession:
                    return jsonify({"error": "Profession utilisateur manquante"}), 403

                # Vérification de l'autorisation de l'utilisateur pour la fonction demandée
                if function_slug not in ALLOWED_FUNCTIONS_BY_PROFESSION.get(profession, []):
                    return jsonify({"error": "Fonction non autorisée pour cette profession"}), 403

                return f(decoded_token, *args, **kwargs)
            except Exception as e:
                print(f"[Auth Error] {e}")
                return jsonify({"error": "Token invalide ou expiré"}), 401
        return wrapper
    return decorator

# -- Sanitize Input --
def sanitize_text(text):
    if not isinstance(text, str): return ""
    text = re.sub(r'[<>;"\'{}\\]', '', text)
    text = re.sub(r'(ignore\s+previous\s+instructions|you\s+are\s+an\s+AI)', '', text, flags=re.IGNORECASE)
    return text.strip()

# === AI Routes === #

@app.route("/ping")
def ping():
    return "pong", 200

@app.route("/ai/summarize", methods=["POST"])
@firebase_token_required("summarize")
def summarize(decoded_token):
    data = request.get_json()
    if not isinstance(data, dict):
        return jsonify({"error": "Requête JSON invalide"}), 400
    text = sanitize_text(data.get("text", ""))
    style = data.get("style", "bullet_points")
    if not text:
        return jsonify({"error": "Texte requis"}), 400
    summary = summarize_text(text, style)
    return jsonify({"summary": summary}), 200

@app.route("/ai/translate", methods=["POST"])
@firebase_token_required("translate")
def translate(decoded_token):
    data = request.get_json()
    if not isinstance(data, dict):
        return jsonify({"error": "Requête JSON invalide"}), 400
    text = sanitize_text(data.get("text", ""))
    lang = data.get("lang", "en")
    if not text:
        return jsonify({"error": "Texte requis"}), 400
    translated = translate_text(text, lang)
    return jsonify({
        "translated_text": translated,
        "original_text": text
    }), 200

@app.route("/ai/correct", methods=["POST"])
@firebase_token_required("correct")
def correct(decoded_token):
    data = request.get_json()
    if not isinstance(data, dict):
        return jsonify({"error": "Requête JSON invalide"}), 400
    text = sanitize_text(data.get("text", ""))
    if not text:
        return jsonify({"error": "Texte requis"}), 400
    corrected = correct_text(text)
    return jsonify({
        "corrected_text": corrected,
        "original_text": text
    }), 200

@app.route("/ai/generate", methods=["POST"])
@firebase_token_required("generate")
def generate(decoded_token):
    data = request.get_json()
    if not isinstance(data, dict):
        return jsonify({"error": "Requête JSON invalide"}), 400
    prompt = sanitize_text(data.get("prompt", ""))
    context = sanitize_text(data.get("context", ""))
    if not prompt:
        return jsonify({"error": "Prompt requis"}), 400
    generated = generate_text(prompt, context)
    return jsonify({"generated": generated}), 200

@app.route("/ai/ocr", methods=["POST"])
@firebase_token_required("ocr")
def ocr(decoded_token):
    data = request.get_json()
    if not isinstance(data, dict):
        return jsonify({"error": "Requête JSON invalide"}), 400
    file_id = data.get("file_id")
    if not file_id:
        return jsonify({"error": "ID de fichier requis"}), 400
    try:
        text = extract_text_from_file(file_id)
        return jsonify({"text": text}), 200
    except Exception as e:
        print(f"[OCR Error] {e}")
        return jsonify({"error": "Échec de l’analyse du fichier"}), 500

@app.route("/ai/chat", methods=["POST"])
@firebase_token_required("generate")
def chat(decoded_token):
    data = request.get_json()
    if not isinstance(data, dict) or "messages" not in data:
        return jsonify({"error": "Requête JSON invalide ou 'messages' manquant"}), 400

    messages = data["messages"]

    # Validation du format attendu
    if not isinstance(messages, list) or not all(
        isinstance(m, dict) and "role" in m and "content" in m for m in messages
    ):
        return jsonify({"error": "Format de messages invalide. Attendu : liste de {'role', 'content'}"}), 400

    # Sanitize seulement les messages de l'utilisateur
    sanitized_messages = []
    for message in messages:
        content = sanitize_text(message["content"]) if message["role"] == "user" else message["content"]
        sanitized_messages.append({
            "role": message["role"],
            "content": content
        })

    try:
        response = generate_chat_response(sanitized_messages)
        return jsonify({"response": response}), 200
    except Exception as e:
        print(f"[Chat Error] {e}")
        return jsonify({"error": "Erreur lors de la génération de réponse"}), 500

@app.route("/ai/verify", methods=["GET"])
@firebase_token_required("summarize")
def verify(decoded_token):
    return jsonify({
        "email": decoded_token["email"],
        "profession": decoded_token.get("profession", "basic")
    }), 200




