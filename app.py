# app.py - VERSIÓN CON TU ESTRUCTURA FIRESTORE
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
# NO usamos variables de entorno para la clave admin
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
    if not plaintext:
        return ""
    plaintext_bytes = plaintext.encode("utf-8")
    nonce = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext_bytes)
    combined = nonce + tag + ciphertext
    return base64.b64encode(combined).decode("utf-8")

def decrypt_aes_gcm(b64_combined: str, key: bytes) -> str:
    if not b64_combined:
        return ""
    try:
        combined = base64.b64decode(b64_combined)
        nonce = combined[0:12]
        tag = combined[12:28]
        ciphertext = combined[28:]
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext.decode("utf-8")
    except Exception as e:
        logger.error(f"Error decrypting data: {e}")
        return ""

# --- Función para obtener clave admin desde TU estructura Firestore ---
def get_admin_key_from_firestore() -> Tuple[bool, str]:
    """
    Obtiene la clave administradora desde Permisos/Clave/Admin
    """
    if not db_admin:
        return False, "Error de servidor: Base de datos no disponible"
    
    try:
        # Obtener la clave almacenada en TU estructura Firestore
        doc_ref = db_admin.collection('Permisos').document('Clave')
        doc = doc_ref.get()
        
        if not doc.exists:
            logger.error("Documento Permisos/Clave no encontrado en Firestore")
            return False, "Configuración de permisos no encontrada"
        
        admin_data = doc.to_dict()
        admin_key = admin_data.get('Admin', '')
        
        if not admin_key:
            logger.error("Campo Admin vacío en Permisos/Clave")
            return False, "Clave administradora no configurada en Firestore"
        
        return True, admin_key
        
    except Exception as e:
        logger.exception("Error obteniendo clave admin desde Firestore")
        return False, f"Error del servidor: {str(e)}"

# --- Función para verificar clave admin ingresada ---
def verify_admin_key(admin_key: str) -> Tuple[bool, str]:
    """
    Verifica la clave administradora ingresada contra Firestore
    """
    if not admin_key:
        return False, "Clave administradora requerida"
    
    # Obtener la clave real desde Firestore
    success, stored_admin_key = get_admin_key_from_firestore()
    if not success:
        return False, stored_admin_key  # stored_admin_key contiene el mensaje de error
    
    # Verificar la clave
    if admin_key != stored_admin_key:
        logger.warning("Intento fallido de autenticación admin")
        return False, "Clave administradora incorrecta"
    
    logger.info("Autenticación admin exitosa")
    return True, "Clave válida"

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

    # Obtener clave admin desde TU estructura Firestore para encriptación
    try:
        success, admin_key = get_admin_key_from_firestore()
        if not success:
            logger.error(f"Error obteniendo clave admin: {admin_key}")
            return jsonify({"ok": False, "msg": "Error de configuración del servidor"}), 500
            
        key = derive_key_from_password(admin_key)

    except Exception as e:
        logger.exception("Error obteniendo clave admin desde Firestore")
        return jsonify({"ok": False, "msg": "Error del servidor obteniendo configuración"}), 500

    if db_admin is None:
        logger.error("Firestore admin client unavailable")
        return jsonify({"ok": False, "msg": "Server error: Firestore admin client unavailable"}), 500

    processed = []
    success_count = 0
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
            success_count += 1
            
            # Registrar en monitoreo
            user_email = token_info.get('email', 'unknown')
            monitor_data = {
                'user_email': user_email,
                'action': 'CARGA_USUARIOS',
                'timestamp': firestore.SERVER_TIMESTAMP,
                'details': f'Cargó usuario: {nombres} {apellidos} - {correo}',
                'ip': request.remote_addr
            }
            db_admin.collection('Monitoreo').add(monitor_data)
            
        except Exception as e:
            logger.exception("Error processing/saving row")
            failed += 1
            # continue with next

    return jsonify({
        "ok": True,
        "msg": f"{success_count} records processed and encrypted, {failed} failed",
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
    
    # Verificar contra TU estructura Firestore
    is_valid, msg = verify_admin_key(admin_key)
    if not is_valid:
        return jsonify({'ok': False, 'msg': msg}), 401

    # Registrar acceso en Monitoreo
    try:
        user_email = token_info.get('email', 'unknown')
        monitor_data = {
            'user_email': user_email,
            'action': 'ACCESO_DATOS_DESCIFRADOS',
            'timestamp': firestore.SERVER_TIMESTAMP,
            'details': 'Accedió a ver los datos descifrados de todos los usuarios',
            'ip': request.remote_addr
        }
        db_admin.collection('Monitoreo').add(monitor_data)
        logger.info(f"Acceso de administrador registrado: {user_email}")
    except Exception as e:
        logger.error(f"Error registrando acceso en monitoreo: {e}")

    # Obtener y descifrar datos
    try:
        users_snap = db_admin.collection('Usuarios').get()
        
        # Derivar la clave para descifrar usando la clave admin
        key = derive_key_from_password(admin_key)
        
        decrypted_data = []
        errors = 0
        
        for doc in users_snap:
            user_data = doc.to_dict()
            
            try:
                # Descifrar los campos cifrados
                dni_dec = decrypt_aes_gcm(user_data.get('DNI_enc', ''), key)
                fecha_dec = decrypt_aes_gcm(user_data.get('FECHA_NAC_enc', ''), key)
                dpto_dec = decrypt_aes_gcm(user_data.get('DPTO_enc', ''), key)
                telefono_dec = decrypt_aes_gcm(user_data.get('TELEFONO_enc', ''), key)
                ubic_dec = decrypt_aes_gcm(user_data.get('UBICACION_enc', ''), key)
                
                decrypted_user = {
                    'id': doc.id,
                    'DNI': dni_dec,
                    'NOMBRES': user_data.get('NOMBRES', ''),
                    'APELLIDOS': user_data.get('APELLIDOS', ''),
                    'FECHA_NAC': fecha_dec,
                    'DPTO': dpto_dec,
                    'CORREO': user_data.get('CORREO', ''),
                    'TELEFONO': telefono_dec,
                    'UBICACION': ubic_dec
                }
                
                decrypted_data.append(decrypted_user)
                
            except Exception as e:
                logger.warning(f"Error descifrando usuario {doc.id}: {e}")
                errors += 1
                continue
        
        logger.info(f"Descifrado completado: {len(decrypted_data)} usuarios, {errors} errores")
        
        return jsonify({
            'ok': True,
            'msg': f'{len(decrypted_data)} registros descifrados, {errors} errores',
            'decryptedData': decrypted_data,
            'stats': {
                'total': len(decrypted_data),
                'successful': len(decrypted_data),
                'errors': errors
            }
        })
        
    except Exception as e:
        logger.exception("Error obteniendo datos")
        return jsonify({'ok': False, 'msg': f'Error obteniendo datos: {str(e)}'}), 500

# Endpoint para verificar permisos admin
@app.route('/verify-admin', methods=['POST'])
def verify_admin():
    try:
        # Aceptar cualquier variante del header Authorization
        auth_header = (
            request.headers.get('Authorization') or
            request.headers.get('authorization') or
            request.headers.get('AUTHORIZATION')
        )

        if not auth_header or not auth_header.startswith("Bearer "):
            return jsonify({"msg": "Token no enviado"}), 401

        # Extraer ID Token Firebase
        id_token = auth_header.split(" ")[1]

        if not id_token:
            return jsonify({"msg": "Token inválido o vacío"}), 401

        # Verificar token Firebase
        try:
            decoded_token = fb_auth.verify_id_token(id_token)
            logger.info(f"Token verificado para usuario: {decoded_token.get('email', 'unknown')}")
        except Exception as e:
            logger.error(f"Error verificando token Firebase: {e}")
            return jsonify({"msg": "Error verificando token Firebase"}), 401

        # Obtener clave enviada por frontend
        data = request.get_json()
        if not data:
            return jsonify({"msg": "Datos JSON requeridos"}), 400
            
        admin_key = data.get('admin_key', '').strip()

        # Verificar contra TU estructura Firestore
        is_valid, msg = verify_admin_key(admin_key)
        if not is_valid:
            logger.warning(f"Intento fallido de verificación admin")
            return jsonify({"msg": msg}), 401

        logger.info("Verificación admin exitosa")
        return jsonify({"msg": "Acceso concedido"}), 200

    except Exception as e:
        logger.exception("Error inesperado en verify-admin")
        return jsonify({"msg": "Error verificando credenciales", "error": str(e)}), 500

# --- Endpoint para verificar estado de la configuración ---
@app.route('/check-admin-config', methods=['GET'])
def check_admin_config():
    """
    Endpoint para verificar si la configuración admin está correcta
    """
    try:
        success, result = get_admin_key_from_firestore()
        if success:
            return jsonify({
                'ok': True, 
                'msg': 'Configuración admin encontrada',
                'config_exists': True
            })
        else:
            return jsonify({
                'ok': False,
                'msg': result,  # result contiene el mensaje de error
                'config_exists': False
            })
    except Exception as e:
        return jsonify({
            'ok': False,
            'msg': f'Error verificando configuración: {str(e)}',
            'config_exists': False
        })

        
# --- Run ---
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
