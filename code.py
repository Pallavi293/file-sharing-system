import os
import jwt
import datetime
import sqlite3
import hashlib
import hmac
from flask import Flask, request, jsonify, send_from_directory, abort
from werkzeug.utils import secure_filename
from functools import wraps

app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = 'supersecretkey123'  # Change to environment var in prod
app.config['UPLOAD_FOLDER'] = 'uploaded_files'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # Max 16 MB files

ALLOWED_EXTENSIONS = {'pptx', 'docx', 'xlsx'}

# Ensure upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# --- Simple SQLite DB setup ---
conn = sqlite3.connect('users_files.db', check_same_thread=False)
cursor = conn.cursor()

# Create tables
cursor.execute('''CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL,
    is_verified INTEGER DEFAULT 0
)''')

cursor.execute('''CREATE TABLE IF NOT EXISTS files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    filename TEXT NOT NULL,
    uploader_id INTEGER NOT NULL,
    upload_time TEXT NOT NULL,
    FOREIGN KEY (uploader_id) REFERENCES users(id)
)''')

conn.commit()

# Utility functions
def hash_password(password):
    # Simple hash with salt using hmac for demonstration
    salt = b'somesaltvalue'
    return hmac.new(salt, password.encode(), hashlib.sha256).hexdigest()

def verify_password(stored_hash, password):
    salt = b'somesaltvalue'
    check_hash = hmac.new(salt, password.encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(stored_hash, check_hash)

def create_jwt_token(data, exp_minutes=60):
    payload = data.copy()
    payload['exp'] = datetime.datetime.utcnow() + datetime.timedelta(minutes=exp_minutes)
    token = jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')
    if isinstance(token, bytes):
        token = token.decode('utf-8')
    return token

def decode_jwt_token(token):
    try:
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except Exception:
        return None

def allowed_file(filename):
    ext = filename.rsplit('.', 1)[1].lower() if '.' in filename else ''
    return ext in ALLOWED_EXTENSIONS

# Auth decorators
def token_required(role=None):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            token = None
            if 'Authorization' in request.headers:
                bearer = request.headers['Authorization']
                if bearer.startswith('Bearer '):
                    token = bearer[7:]
            if not token:
                return jsonify({'message': 'Token is missing!'}), 401
            data = decode_jwt_token(token)
            if not data:
                return jsonify({'message': 'Token is invalid or expired!'}), 401
            # Check role if needed
            if role and data.get('role') != role:
                return jsonify({'message': 'Unauthorized role'}), 403
            # Attach user info to request context
            request.user = data
            return f(*args, **kwargs)
        return wrapper
    return decorator

# --- Ops User APIs ---

@app.route('/ops/login', methods=['POST'])
def ops_login():
    data = request.json
    if not data or not data.get('email') or not data.get('password'):
        return jsonify({'message': 'Email and password required'}), 400
    email = data['email']
    password = data['password']
    cursor.execute('SELECT id, password_hash FROM users WHERE email=? AND role="ops"', (email,))
    row = cursor.fetchone()
    if not row:
        return jsonify({'message': 'Ops user not found'}), 404
    user_id, stored_hash = row
    if not verify_password(stored_hash, password):
        return jsonify({'message': 'Incorrect password'}), 401
    token = create_jwt_token({'id': user_id, 'email': email, 'role': 'ops'}, exp_minutes=120)
    return jsonify({'token': token})

@app.route('/ops/upload', methods=['POST'])
@token_required(role='ops')
def ops_upload():
    if 'file' not in request.files:
        return jsonify({'message': 'No file part'}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({'message': 'No selected file'}), 400
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        # Avoid overwrite by appending timestamp if file exists
        if os.path.exists(filepath):
            name, ext = os.path.splitext(filename)
            timestamp = datetime.datetime.utcnow().strftime('%Y%m%d%H%M%S')
            filename = f"{name}_{timestamp}{ext}"
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)

        # Save file info to DB
        uploader_id = request.user['id']
        upload_time = datetime.datetime.utcnow().isoformat()
        cursor.execute('INSERT INTO files (filename, uploader_id, upload_time) VALUES (?, ?, ?)',
                       (filename, uploader_id, upload_time))
        conn.commit()

        return jsonify({'message': 'File uploaded successfully', 'filename': filename})
    else:
        return jsonify({'message': 'File type not allowed. Allowed types: pptx, docx, xlsx'}), 400

# --- Client User APIs ---

@app.route('/client/signup', methods=['POST'])
def client_signup():
    data = request.json
    if not data or not data.get('email') or not data.get('password'):
        return jsonify({'message': 'Email and password required'}), 400
    email = data['email'].lower()
    password = data['password']
    cursor.execute('SELECT id FROM users WHERE email=?', (email,))
    if cursor.fetchone():
        return jsonify({'message': 'Email already registered'}), 400
    password_hash = hash_password(password)
    cursor.execute('INSERT INTO users (email, password_hash, role, is_verified) VALUES (?, ?, "client", 0)',
                   (email, password_hash))
    conn.commit()

    # Generate email verification token with encrypted URL (JWT)
    user_id = cursor.lastrowid
    token = create_jwt_token({'user_id': user_id, 'email': email, 'action': 'verify_email'}, exp_minutes=60*24)
    verify_url = f"{request.host_url}client/verify_email/{token}"

    # Simulate email sending (print to console)
    print(f"Verification email sent to {email} with link: {verify_url}")

    # Return encrypted URL in response as well
    return jsonify({'message': 'User registered successfully. Verification email sent.', 'verification_url': verify_url})

@app.route('/client/verify_email/<token>', methods=['GET'])
def client_verify_email(token):
    data = decode_jwt_token(token)
    if not data or data.get('action') != 'verify_email':
        return jsonify({'message': 'Invalid or expired token'}), 400
    user_id = data.get('user_id')
    cursor.execute('SELECT is_verified FROM users WHERE id=?', (user_id,))
    row = cursor.fetchone()
    if not row:
        return jsonify({'message': 'User not found'}), 404
    if row[0] == 1:
        return jsonify({'message': 'Email already verified'})
    cursor.execute('UPDATE users SET is_verified=1 WHERE id=?', (user_id,))
    conn.commit()
    return jsonify({'message': 'Email verified successfully. You can now login.'})

@app.route('/client/login', methods=['POST'])
def client_login():
    data = request.json
    if not data or not data.get('email') or not data.get('password'):
        return jsonify({'message': 'Email and password required'}), 400
    email = data['email'].lower()
    password = data['password']
    cursor.execute('SELECT id, password_hash, is_verified FROM users WHERE email=? AND role="client"', (email,))
    row = cursor.fetchone()
    if not row:
        return jsonify({'message': 'Client user not found'}), 404
    user_id, stored_hash, is_verified = row
    if not is_verified:
        return jsonify({'message': 'Email not verified'}), 403
    if not verify_password(stored_hash, password):
        return jsonify({'message': 'Incorrect password'}), 401
    token = create_jwt_token({'id': user_id, 'email': email, 'role': 'client'}, exp_minutes=120)
    return jsonify({'token': token})

@app.route('/client/files', methods=['GET'])
@token_required(role='client')
def client_list_files():
    # List all files uploaded by Ops users, with info
    cursor.execute('''
        SELECT files.id, files.filename, files.upload_time, users.email AS uploader_email
        FROM files JOIN users ON files.uploader_id = users.id
        ORDER BY files.upload_time DESC
    ''')
    files = cursor.fetchall()
    files_list = []
    for f in files:
        fid, fname, ftime, uploader = f
        # Create encrypted download URL token for the file (JWT)
        token = create_jwt_token({'file_id': fid, 'user_id': request.user['id'], 'action': 'download'}, exp_minutes=30)
        download_url = f"{request.host_url}client/download/{fid}?token={token}"
        files_list.append({
            'id': fid,
            'filename': fname,
            'uploaded_at': ftime,
            'uploaded_by': uploader,
            'download_url': download_url
        })
    return jsonify({'files': files_list})

@app.route('/client/download/<int:file_id>', methods=['GET'])
def client_download_file(file_id):
    # Token for download required in query parameter
    token = request.args.get('token')
    if not token:
        return jsonify({'message': 'Download token is missing'}), 401
    data = decode_jwt_token(token)
    if not data or data.get('action') != 'download' or data.get('file_id') != file_id:
        return jsonify({'message': 'Invalid or expired token'}), 403

    # Check user is client and actually logged in (token)
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({'message': 'Missing authorization token'}), 401
    user_token = auth_header[7:]
    user_data = decode_jwt_token(user_token)
    if not user_data or user_data.get('role') != 'client' or user_data.get('id') != data.get('user_id'):
        return jsonify({'message': 'Invalid or expired user token'}), 403

    # Find file info
    cursor.execute('SELECT filename FROM files WHERE id=?', (file_id,))
    row = cursor.fetchone()
    if not row:
        return jsonify({'message': 'File not found'}), 404
    filename = row[0]

    try:
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)
    except FileNotFoundError:
        return jsonify({'message': 'File missing on server'}), 404

@app.route('/')
def index():
    return jsonify({'message': 'Secure File Sharing API is running'})

if __name__ == '__main__':
    app.run(debug=True)

