# app.py
import os
import json
import logging
import base64
import secrets
import requests
from io import BytesIO
from typing import Tuple

from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
import pandas as pd

from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

import firebase_admin
from firebase_admin import auth as fb_auth, credentials, firestore as admin_firestore

# --- Logging ---
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("reniec-backend")

# --- Config ---
BASE_DIR = os.path.dirname(__file__)
SALT_FILE = os.path.join(BASE_DIR, "salt.bin")
SALT_SIZE = 16
PBKDF2_ITERS = 200_000

RECAPTCHA_SECRET = os.getenv("RECAPTCHA_SECRET", "YOUR_FALLBACK_SECRET")
ADMIN_PASS = os.getenv("ADMIN_PASS")  # must be set in production
SERVICE_ACCOUNT_JSON = os.getenv("SERVICE_ACCOUNT_JSON")
SERVICE_ACCOUNT_PATH = os.path.join(BASE_DIR, "serviceAccountKey.json")

# --- Flask app ---
app = Flask(__name__)
# Allow all origins in development; restrict in production via env if desired
cors_origins = os.getenv("CORS_ORIGINS", "*")
CORS(app, resources={r"/*": {"origins": cors_origins}})
app.secret_key = secrets.token_hex(32)

# --- Firebase initialization ---
def init_firebase() -> None:
    """
    Initialize Firebase admin SDK using either:
      - JSON string provided in SERVICE_ACCOUNT_JSON env var, or
      - JSON file at SERVICE_ACCOUNT_PATH
    Raises FileNotFoundError if neither is present.
    """
    if firebase_admin._apps:
        logger.info("Firebase already initialized")
        return

    if SERVICE_ACCOUNT_JSON:
        logger.info("Initializing Firebase from SERVICE_ACCOUNT_JSON env var")
        try:
            sa_info = json.loads(SERVICE_ACCOUNT_JSON)
        except Exception as e:
            logger.exception("SERVICE_ACCOUNT_JSON is not valid JSON")
            raise RuntimeError("SERVICE_ACCOUNT_JSON is not valid JSON") from e
        try:
            cred = credentials.Certificate(sa_info)
            firebase_admin.initialize_app(cred)
            logger.info("Firebase initialized from env var")
            return
        except Exception as e:
            logger.exception("Failed to initialize Firebase from SERVICE_ACCOUNT_JSON")
            raise

    # fallback: try file on disk
    if os.path.exists(SERVICE_ACCOUNT_PATH):
        logger.info("Initializing Firebase from serviceAccountKey.json file")
        try:
            cred = credentials.Certificate(SERVICE_ACCOUNT_PATH)
            firebase_admin.initialize_app(cred)
            logger.info("Firebase initialized from file")
            return
        except Exception as e:
            logger.exception("Failed to initialize Firebase from file")
            raise

    # if we reach here, no credentials available
    raise FileNotFoundError(
        f"Firebase service account not found. Provide SERVICE_ACCOUNT_JSON env var "
        f"or place serviceAccountKey.json at: {SERVICE_ACCOUNT_PATH}"
    )

# Try to initialize Firebase now (will raise if not provided)
try:
    init_firebase()
except Exception as e:
    logger.exception("Firebase initialization failed")
    raise

# create admin firestore client
try:
    db_admin = admin_firestore.client()
except Exception as e:
    logger.exception("Failed to create admin firestore client")
    db_admin = None

# --- Crypto helpers ---
def ensure_salt() -> bytes:
    if not os.path.exists(SALT_FILE):
        s = get_random_bytes(SALT_SIZE)
        with open(SALT_FILE, "wb") as f:
            f.write(s)
        return s
    with open(SALT_FILE, "rb") as f:
        return f.read()

def derive_key_from_password(password: str) -> bytes:
    salt = ensure_salt()
    return PBKDF2(password.encode("utf-8"), salt, dkLen=32, count=PBKDF2_ITERS)

def encrypt_aes_gcm(plaintext: str, key: bytes) -> str:
    plaintext_bytes = plaintext.encode("utf-8")
    nonce = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext_bytes)
    combined = nonce + tag + ciphertext
    return base64.b64encode(combined).decode("utf-8")

def decrypt_aes_gcm(b64_combined: str, key: bytes) -> str:
    combined = base64.b64decode(b64_combined)
    nonce = combined[0:12]
    tag = combined[12:28]
    ciphertext = combined[28:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext.decode("utf-8")

# --- reCAPTCHA verification ---
def verify_recaptcha_token(token: str, remoteip: str = None) -> Tuple[bool, dict]:
    url = "https://www.google.com/recaptcha/api/siteverify"
    payload = {"secret": RECAPTCHA_SECRET, "response": token}
    if remoteip:
        payload["remoteip"] = remoteip
    try:
        r = requests.post(url, data=payload, timeout=10)
        r.raise_for_status()
        jr = r.json()
        ok = bool(jr.get("success"))
        return ok, jr
    except requests.RequestException as e:
        logger.exception("Network error contacting reCAPTCHA service")
        return False, {"error": "network error", "detail": str(e)}
    except ValueError:
        logger.exception("Invalid JSON from reCAPTCHA service")
        return False, {"error": "invalid json"}

# --- Firebase idToken verification ---
def verify_id_token(id_token: str) -> Tuple[bool, dict | str]:
    try:
        decoded = fb_auth.verify_id_token(id_token)
        return True, decoded
    except Exception as e:
        logger.exception("Failed to verify Firebase idToken")
        return False, str(e)

# --- Endpoints ---
@app.route("/healthz")
def healthz():
    return jsonify({"ok": True}), 200

@app.route("/verify-recaptcha", methods=["POST"])
def route_verify_recaptcha():
    data = request.get_json() or {}
    token = data.get("token")
    if not token:
        return jsonify({"ok": False, "msg": "Token missing"}), 400
    ok, details = verify_recaptcha_token(token, request.remote_addr)
    if not ok:
        return jsonify({"ok": False, "msg": "reCAPTCHA failed", "details": details}), 400
    return jsonify({"ok": True})

@app.route("/download-template")
def download_template():
    sample = pd.DataFrame(
        [
            {
                "DNI": "12345678",
                "NOMBRES": "JUAN",
                "APELLIDOS": "PEREZ",
                "FECHA_NAC": "1990-01-01",
                "DPTO": "LIMA",
                "CORREO": "juan.perez@example.com",
                "TELEFONO": "987654321",
                "UBICACION": "Av. Ejemplo 123, Lima",
            }
        ]
    )
    out = BytesIO()
    sample.to_excel(out, index=False)
    out.seek(0)
    return send_file(out, download_name="template_usuarios.xlsx", as_attachment=True)

@app.route("/upload", methods=["POST"])
def upload():
    # Verify Authorization header (Firebase idToken) - required
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return jsonify({"ok": False, "msg": "Authorization header missing or malformed"}), 401
    id_token = auth_header.split(" ", 1)[1]
    valid_token, token_info = verify_id_token(id_token)
    if not valid_token:
        return jsonify({"ok": False, "msg": "Invalid idToken", "detail": token_info}), 401

    # reCAPTCHA token validation (optional if idToken present)
    recaptcha_token = request.form.get("recaptcha") or request.files.get("recaptcha")
    if recaptcha_token:
        ok, details = verify_recaptcha_token(recaptcha_token, request.remote_addr)
        if not ok:
            return jsonify({"ok": False, "msg": "reCAPTCHA validation failed", "details": details}), 400
    else:
        # no reCAPTCHA provided — allow if idToken is valid (you may change this policy)
        logger.info("No reCAPTCHA token provided; proceeding because idToken was valid")

    # file
    if "file" not in request.files:
        return jsonify({"ok": False, "msg": "No file uploaded"}), 400
    file = request.files["file"]
    try:
        df = pd.read_excel(file)
    except Exception as e:
        logger.exception("Error reading Excel file")
        return jsonify({"ok": False, "msg": f"Error reading Excel: {e}"}), 400

    required = ["DNI", "NOMBRES", "APELLIDOS", "FECHA_NAC", "DPTO", "CORREO", "TELEFONO", "UBICACION"]
    missing = [h for h in required if h not in df.columns]
    if missing:
        return jsonify({"ok": False, "msg": f"Missing columns: {missing}"}), 400

    admin_pass = ADMIN_PASS
    if not admin_pass:
        logger.error("ADMIN_PASS is not set in environment")
        return jsonify({"ok": False, "msg": "ADMIN_PASS not set on server"}), 500

    key = derive_key_from_password(admin_pass)

    if db_admin is None:
        logger.error("Firestore admin client unavailable")
        return jsonify({"ok": False, "msg": "Server error: Firestore admin client unavailable"}), 500

    processed = []
    success = 0
    failed = 0
    for _, row in df.iterrows():
        try:
            dni_raw = str(row["DNI"]).strip()
            ubic = str(row.get("UBICACION", "")).strip()
            dni_enc = encrypt_aes_gcm(dni_raw, key) if dni_raw != '' else ''
            ubic_enc = encrypt_aes_gcm(ubic, key) if ubic else ""
            doc_obj = {
                "DNI_enc": dni_enc,
                "NOMBRES": str(row.get("NOMBRES", "") or ""),
                "APELLIDOS": str(row.get("APELLIDOS", "") or ""),
                "FECHA_NAC": str(row.get("FECHA_NAC", "") or ""),
                "DPTO": str(row.get("DPTO", "") or ""),
                "CORREO": str(row.get("CORREO", "") or ""),
                "TELEFONO": str(row.get("TELEFONO", "") or ""),
                "UBICACION_enc": ubic_enc,
                "createdAt": admin_firestore.SERVER_TIMESTAMP
            }
            # Guarda con Firestore Admin (colección 'Usuarios')
            db_admin.collection("Usuarios").add(doc_obj)
            processed.append(doc_obj)
            success += 1
        except Exception as e:
            logger.exception("Error processing/saving row")
            failed += 1
            # continúa con el siguiente

    return jsonify({
        "ok": True,
        "msg": f"{success} records processed and encrypted, {failed} failed",
        "preview": processed
    })

# --- Run ---
if __name__ == "__main__":
    # When running locally you can set PORT in env or default to 5000
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)

