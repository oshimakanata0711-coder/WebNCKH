import os
import secrets
from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from werkzeug.utils import secure_filename
from secretsharing import PlaintextToHexSecretSharer
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend

# --- Khởi tạo Flask App ---
app = Flask(__name__)
# Cấu hình CORS đầy đủ để tránh lỗi khi gọi từ Frontend
CORS(app, resources={r"/*": {"origins": "*"}}) 

# --- Cấu hình đường dẫn thư mục uploads chuẩn ---
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# --- 1. Hàm tạo/lấy khóa RSA ---
def get_or_create_rsa_keys(password: str):
    private_path = os.path.join(BASE_DIR, "private_key.pem")
    public_path = os.path.join(BASE_DIR, "public_key.pem")

    if not os.path.exists(private_path):
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        with open(private_path, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.BestAvailableEncryption(password.encode())
            ))
        public_key = private_key.public_key()
        with open(public_path, "wb") as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
        return private_key, public_key
    else:
        with open(private_path, "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=password.encode())
        with open(public_path, "rb") as f:
            public_key = serialization.load_pem_public_key(f.read())
        return private_key, public_key

# --- 2. Hàm mã hóa file bằng AES ---
def encrypt_file(file_path):
    aes_key = os.urandom(32)
    iv = os.urandom(16)
    with open(file_path, 'rb') as f:
        data = f.read()
    
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(data) + encryptor.finalize()
    
    enc_path = file_path + ".enc"
    with open(enc_path, 'wb') as f:
        f.write(iv + encrypted_data)
    return aes_key, enc_path

# --- 3. API Mã hóa ---
@app.route('/api/encrypt', methods=['POST'])
def api_encrypt():
    if 'file' not in request.files:
        return jsonify({"status": "error", "message": "Không tìm thấy file"}), 400
        
    uploaded_file = request.files['file']
    if uploaded_file.filename == '':
        return jsonify({"status": "error", "message": "Tên file trống"}), 400

    # Lấy tham số và ép kiểu an toàn
    try:
        rsa_pass = request.form.get('rsa_pass', 'admin123')
        n = int(request.form.get('n', 5))
        k = int(request.form.get('k', 3))
    except ValueError:
        return jsonify({"status": "error", "message": "n và k phải là số nguyên"}), 400

    filename = secure_filename(uploaded_file.filename)
    file_path = os.path.join(UPLOAD_FOLDER, filename)
    uploaded_file.save(file_path)

    try:
        # Xử lý mã hóa RSA & AES
        priv_key, pub_key = get_or_create_rsa_keys(rsa_pass)
        raw_aes_key, enc_path = encrypt_file(file_path)
        
        session_salt = secrets.token_hex(4)
        combined_secret = raw_aes_key.hex() + ":" + session_salt

        # Mã hóa AES Key bằng RSA
        encrypted_session_secret = pub_key.encrypt(
            combined_secret.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()), 
                algorithm=hashes.SHA256(), 
                label=None
            )
        )

        # Chia sẻ bí mật (Shamir's Secret Sharing)
        shares = PlaintextToHexSecretSharer.split_secret(encrypted_session_secret.hex(), k, n)

        # Xóa file gốc sau khi đã có file .enc (Bảo mật)
        if os.path.exists(file_path):
            os.remove(file_path)

        # Tạo link download dựa trên host hiện tại (Render/Local)
        # Lưu ý: Dùng https nếu chạy trên Render
        protocol = "https" if "render.com" in request.host else "http"
        download_url = f"{protocol}://{request.host}/download/{os.path.basename(enc_path)}"

        return jsonify({
            "status": "success",
            "filename": os.path.basename(enc_path),
            "session_salt": session_salt,
            "shares": shares,
            "download_url": download_url
        })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

# --- 4. API Download ---
@app.route('/download/<filename>')
def download_file(filename):
    file_path = os.path.join(UPLOAD_FOLDER, filename)
    if os.path.exists(file_path):
        return send_file(file_path, as_attachment=True)
    return jsonify({"status": "error", "message": "File không tồn tại"}), 404

# --- Khởi chạy Server ---
if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
