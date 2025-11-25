# app.py
import os
import json
import logging
import base64
import secrets
import requests
from io import BytesIO
from typing import Tuple
from firebase_admin import firestore
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
cors_origins = os.getenv("CORS_ORIGINS", "*")
CORS(app, resources={r"/*": {"origins": cors_origins}})
app.secret_key = secrets.token_hex(32)

# --- Firebase initialization ---
def init_firebase() -> None:
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

    raise FileNotFoundError(
        f"Firebase service account not found. Provide SERVICE_ACCOUNT_JSON env var "
        f"or place serviceAccountKey.json at: {SERVICE_ACCOUNT_PATH}"
    )

try:
    init_firebase()
except Exception as e:
    logger.exception("Firebase initialization failed")
    raise

# admin firestore client
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
            # plaintext fields
            nombres = str(row.get("NOMBRES", "") or "").strip()
            apellidos = str(row.get("APELLIDOS", "") or "").strip()
            correo = str(row.get("CORREO", "") or "").strip()

            # fields to encrypt
            dni_raw = str(row.get("DNI", "") or "").strip()
            fecha_raw = str(row.get("FECHA_NAC", "") or "").strip()
            dpto_raw = str(row.get("DPTO", "") or "").strip()
            telefono_raw = str(row.get("TELEFONO", "") or "").strip()
            ubic_raw = str(row.get("UBICACION", "") or "").strip()

            dni_enc = encrypt_aes_gcm(dni_raw, key) if dni_raw != '' else ''
            fecha_enc = encrypt_aes_gcm(fecha_raw, key) if fecha_raw != '' else ''
            dpto_enc = encrypt_aes_gcm(dpto_raw, key) if dpto_raw != '' else ''
            telefono_enc = encrypt_aes_gcm(telefono_raw, key) if telefono_raw != '' else ''
            ubic_enc = encrypt_aes_gcm(ubic_raw, key) if ubic_raw != '' else ''

            doc_obj = {
                "DNI_enc": dni_enc,
                "NOMBRES": nombres,
                "APELLIDOS": apellidos,
                "FECHA_NAC_enc": fecha_enc,
                "DPTO_enc": dpto_enc,
                "CORREO": correo,
                "TELEFONO_enc": telefono_enc,
                "UBICACION_enc": ubic_enc,
                "createdAt": admin_firestore.SERVER_TIMESTAMP
            }

            db_admin.collection("Usuarios").add(doc_obj)
            processed.append(doc_obj)
            success += 1
        except Exception as e:
            logger.exception("Error processing/saving row")
            failed += 1
            # continue with next

    return jsonify({
        "ok": True,
        "msg": f"{success} records processed and encrypted, {failed} failed",
        "preview": processed
    })

@app.route('/decrypt-data', methods=['POST'])
def decrypt_data():
    # Verificar Authorization header
    auth_header = request.headers.get('Authorization', '')
    if not auth_header.startswith('Bearer '):
        return jsonify({'ok': False, 'msg': 'Authorization header missing or malformed'}), 401
    
    id_token = auth_header.split(' ', 1)[1]
    valid_token, token_info = verify_id_token(id_token)
    if not valid_token:
        return jsonify({'ok': False, 'msg': 'Invalid idToken', 'detail': token_info}), 401

    data = request.get_json() or {}
    admin_key = data.get('admin_key')
    
    if not admin_key:
        return jsonify({'ok': False, 'msg': 'Clave administradora requerida'}), 400

    # Verificar clave administradora
    try:
        doc_ref = db_admin.collection('Permisos').doc('Clave')
        doc = doc_ref.get()
        
        if not doc.exists:
            return jsonify({'ok': False, 'msg': 'Configuración de permisos no encontrada'}), 500
        
        stored_key = doc.to_dict().get('Admin')
        if admin_key != stored_key:
            return jsonify({'ok': False, 'msg': 'Clave administradora incorrecta'}), 401
    except Exception as e:
        logger.exception("Error verificando clave administradora")
        return jsonify({'ok': False, 'msg': 'Error verificando credenciales'}), 500

    # Registrar acceso en Monitoreo
    try:
        user_email = token_info.get('email', 'unknown')
        monitor_data = {
            'user_email': user_email,
            'action': 'ACCESS_DECRYPTED_DATA',
            'timestamp': firestore.SERVER_TIMESTAMP,
            'details': 'Acceso a datos descifrados - Verificación exitosa',
            'ip': request.remote_addr
        }
        db_admin.collection('Monitoreo').add(monitor_data)
        logger.info(f"Acceso de administrador registrado: {user_email}")
    except Exception as e:
        logger.error(f"Error registrando acceso en monitoreo: {e}")

    # Obtener datos (sin intentar descifrar ya que están en texto plano)
    try:
        users_snap = db_admin.collection('Usuarios').get()
        
        decrypted_data = []
        
        for doc in users_snap:
            user_data = doc.to_dict()
            
            try:
                # Los datos ya están en texto plano, simplemente extraerlos
                decrypted_user = {
                    'id': doc.id,
                    'DNI': user_data.get('DNI', ''),
                    'NOMBRES': user_data.get('NOMBRES', ''),
                    'APELLIDOS': user_data.get('APELLIDOS', ''),
                    'FECHA_NAC': user_data.get('FECHA_NAC', ''),
                    'DPTO': user_data.get('DPTO', ''),
                    'CORREO': user_data.get('CORREO', ''),
                    'TELEFONO': user_data.get('TELEFONO', ''),
                    'UBICACION': user_data.get('UBICACION', '')
                }
                
                decrypted_data.append(decrypted_user)
                
            except Exception as e:
                logger.warning(f"Error procesando usuario {doc.id}: {e}")
                continue
        
        logger.info(f"Proceso completado: {len(decrypted_data)} usuarios procesados")
        
        return jsonify({
            'ok': True,
            'msg': f'{len(decrypted_data)} registros cargados correctamente',
            'decryptedData': decrypted_data,
            'stats': {
                'total': len(decrypted_data),
                'successful': len(decrypted_data),
                'errors': 0
            }
        })
        
    except Exception as e:
        logger.exception("Error obteniendo datos")
        return jsonify({'ok': False, 'msg': f'Error obteniendo datos: {str(e)}'}), 500

# Endpoint para obtener registros de monitoreo
@app.route('/get-monitoring', methods=['GET'])
def get_monitoring():
    # Verificar Authorization header
    auth_header = request.headers.get('Authorization', '')
    if not auth_header.startswith('Bearer '):
        return jsonify({'ok': False, 'msg': 'Authorization header missing or malformed'}), 401
    
    id_token = auth_header.split(' ', 1)[1]
    valid_token, token_info = verify_id_token(id_token)
    if not valid_token:
        return jsonify({'ok': False, 'msg': 'Invalid idToken', 'detail': token_info}), 401

    # Verificar que sea administrador
    data = request.get_json() or {}
    admin_key = data.get('admin_key')
    
    if not admin_key:
        return jsonify({'ok': False, 'msg': 'Clave administradora requerida'}), 400

    try:
        doc_ref = db_admin.collection('Permisos').doc('Clave')
        doc = doc_ref.get()
        
        if not doc.exists or admin_key != doc.to_dict().get('Admin'):
            return jsonify({'ok': False, 'msg': 'Clave administradora incorrecta'}), 401
    except Exception as e:
        return jsonify({'ok': False, 'msg': 'Error verificando credenciales'}), 500

    # Obtener registros de monitoreo
    try:
        monitoring_ref = db_admin.collection('Monitoreo').order_by('timestamp', direction=firestore.Query.DESCENDING).limit(100)
        monitoring_snap = monitoring_ref.get()
        
        monitoring_data = []
        for doc in monitoring_snap:
            record = doc.to_dict()
            record['id'] = doc.id
            # Convertir timestamp a string legible
            if 'timestamp' in record and hasattr(record['timestamp'], 'strftime'):
                record['timestamp'] = record['timestamp'].strftime('%Y-%m-%d %H:%M:%S')
            monitoring_data.append(record)
        
        return jsonify({
            'ok': True,
            'monitoringData': monitoring_data,
            'total': len(monitoring_data)
        })
        
    except Exception as e:
        logger.exception("Error obteniendo datos de monitoreo")
        return jsonify({'ok': False, 'msg': f'Error obteniendo monitoreo: {str(e)}'}), 500
        

# Endpoint para registrar acciones manualmente
@app.route('/log-action', methods=['POST'])
def log_action():
    # Verificar Authorization header
    auth_header = request.headers.get('Authorization', '')
    if not auth_header.startswith('Bearer '):
        return jsonify({'ok': False, 'msg': 'Authorization header missing or malformed'}), 401
    
    id_token = auth_header.split(' ', 1)[1]
    valid_token, token_info = verify_id_token(id_token)
    if not valid_token:
        return jsonify({'ok': False, 'msg': 'Invalid idToken', 'detail': token_info}), 401

    data = request.get_json() or {}
    action = data.get('action', 'UNKNOWN_ACTION')
    details = data.get('details', '')
    
    try:
        user_email = token_info.get('email', 'unknown')
        monitor_data = {
            'user_email': user_email,
            'action': action,
            'timestamp': firestore.SERVER_TIMESTAMP,
            'details': details,
            'ip': request.remote_addr
        }
        db_admin.collection('Monitoreo').add(monitor_data)
        
        return jsonify({'ok': True, 'msg': 'Acción registrada correctamente'})
        
    except Exception as e:
        logger.error(f"Error registrando acción: {e}")
        return jsonify({'ok': False, 'msg': f'Error registrando acción: {str(e)}'}), 500
        
# --- Run ---
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
