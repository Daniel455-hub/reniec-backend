# app.py
import os, base64, secrets, requests
from io import BytesIO
from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
import pandas as pd
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import firebase_admin
from firebase_admin import auth as fb_auth, credentials

# CONFIG
SALT_FILE = os.path.join(os.path.dirname(__file__), 'salt.bin')
SALT_SIZE = 16
PBKDF2_ITERS = 200_000
RECAPTCHA_SECRET = os.getenv('RECAPTCHA_SECRET', 'YOUR_FALLBACK_SECRET')

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})
app.secret_key = secrets.token_hex(16)

# ---------- Service account handling ----------
service_path = os.path.join(os.path.dirname(__file__), 'serviceAccountKey.json')

# If Render (or you) provides the service account JSON in an ENV var, write it to file at startup
svc_json_env = os.getenv('SERVICE_ACCOUNT_JSON')
if svc_json_env and not os.path.exists(service_path):
    with open(service_path, 'w', encoding='utf-8') as f:
        f.write(svc_json_env)

if not os.path.exists(service_path):
    raise FileNotFoundError(f"Place your serviceAccountKey.json in: {service_path} or set SERVICE_ACCOUNT_JSON env var")
cred = credentials.Certificate(service_path)
firebase_admin.initialize_app(cred)

# ---------- CRYPTO helpers ----------
def ensure_salt():
    if not os.path.exists(SALT_FILE):
        s = get_random_bytes(SALT_SIZE)
        with open(SALT_FILE, 'wb') as f:
            f.write(s)
        return s
    with open(SALT_FILE, 'rb') as f:
        return f.read()

def derive_key_from_password(password: str):
    salt = ensure_salt()
    return PBKDF2(password.encode('utf-8'), salt, dkLen=32, count=PBKDF2_ITERS)

def encrypt_aes_gcm(plaintext: str, key: bytes) -> str:
    plaintext_bytes = plaintext.encode('utf-8')
    nonce = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext_bytes)
    combined = nonce + tag + ciphertext
    return base64.b64encode(combined).decode('utf-8')

def decrypt_aes_gcm(b64_combined: str, key: bytes) -> str:
    combined = base64.b64decode(b64_combined)
    nonce = combined[0:12]
    tag = combined[12:28]
    ciphertext = combined[28:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext.decode('utf-8')

# ---------- reCAPTCHA ----------
def verify_recaptcha_token(token: str, remoteip: str = None):
    url = 'https://www.google.com/recaptcha/api/siteverify'
    payload = {'secret': RECAPTCHA_SECRET, 'response': token}
    if remoteip:
        payload['remoteip'] = remoteip
    try:
        r = requests.post(url, data=payload, timeout=10)
        r.raise_for_status()
        jr = r.json()
        return jr.get('success', False), jr
    except Exception as e:
        return False, {'error': str(e)}

# ---------- Firebase idToken verification ----------
def verify_id_token(id_token: str):
    try:
        decoded = fb_auth.verify_id_token(id_token)
        return True, decoded
    except Exception as e:
        return False, str(e)

# ---------- Endpoints ----------
@app.route('/verify-recaptcha', methods=['POST'])
def route_verify_recaptcha():
    data = request.get_json() or {}
    token = data.get('token')
    if not token:
        return jsonify({'ok': False, 'msg': 'Token missing'}), 400
    ok, details = verify_recaptcha_token(token, request.remote_addr)
    if not ok:
        return jsonify({'ok': False, 'msg': 'reCAPTCHA failed', 'details': details}), 400
    return jsonify({'ok': True})

@app.route('/download-template')
def download_template():
    sample = pd.DataFrame([{
        'DNI': '12345678',
        'NOMBRES': 'JUAN',
        'APELLIDOS': 'PEREZ',
        'FECHA_NAC': '1990-01-01',
        'DPTO': 'LIMA',
        'CORREO': 'juan.perez@example.com',
        'TELEFONO': '987654321',
        'UBICACION': 'Av. Ejemplo 123, Lima'
    }])
    out = BytesIO()
    sample.to_excel(out, index=False)
    out.seek(0)
    return send_file(out, download_name='template_usuarios.xlsx', as_attachment=True)

@app.route('/upload', methods=['POST'])
def upload():
    auth_header = request.headers.get('Authorization', '')
    if not auth_header.startswith('Bearer '):
        return jsonify({'ok': False, 'msg': 'Authorization header missing or malformed'}), 401
    id_token = auth_header.split(' ')[1]
    valid_token, token_info = verify_id_token(id_token)
    if not valid_token:
        return jsonify({'ok': False, 'msg': 'Invalid idToken', 'detail': token_info}), 401

    recaptcha_token = request.form.get('recaptcha') or request.files.get('recaptcha')
    if not recaptcha_token:
        return jsonify({'ok': False, 'msg': 'recaptcha token missing'}), 400
    ok, details = verify_recaptcha_token(recaptcha_token, request.remote_addr)
    if not ok:
        return jsonify({'ok': False, 'msg': 'reCAPTCHA validation failed', 'details': details}), 400

    if 'file' not in request.files:
        return jsonify({'ok': False, 'msg': 'No file uploaded'}), 400
    file = request.files['file']
    try:
        df = pd.read_excel(file)
    except Exception as e:
        return jsonify({'ok': False, 'msg': f'Error reading Excel: {e}'}), 400

    required = ['DNI', 'NOMBRES', 'APELLIDOS', 'FECHA_NAC', 'DPTO', 'CORREO', 'TELEFONO', 'UBICACION']
    missing = [h for h in required if h not in df.columns]
    if missing:
        return jsonify({'ok': False, 'msg': f'Missing columns: {missing}'}), 400

    admin_pass = os.getenv('ADMIN_PASS')
    if not admin_pass:
        return jsonify({'ok': False, 'msg': 'ADMIN_PASS not set on server'}, 500)

    key = derive_key_from_password(admin_pass)

    processed = []
    for _, row in df.iterrows():
        dni_raw = str(row['DNI']).strip()
        ubic = str(row.get('UBICACION','')).strip()
        dni_enc = encrypt_aes_gcm(dni_raw, key)
        ubic_enc = encrypt_aes_gcm(ubic, key) if ubic else ''
        processed.append({
            'DNI_enc': dni_enc,
            'NOMBRES': row.get('NOMBRES',''),
            'APELLIDOS': row.get('APELLIDOS',''),
            'FECHA_NAC': str(row.get('FECHA_NAC','')),
            'DPTO': row.get('DPTO',''),
            'CORREO': row.get('CORREO',''),
            'TELEFONO': row.get('TELEFONO',''),
            'UBICACION_enc': ubic_enc
        })

    return jsonify({'ok': True, 'msg': f'{len(processed)} records processed and encrypted', 'preview': processed})

# Run locally with: python app.py
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=True)
