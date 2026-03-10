import os, secrets
from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from secretsharing import PlaintextToHexSecretSharer
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from flask_cors import CORS # Cài: pip install flask-cors


# --- Giữ nguyên hàm tạo khóa RSA của bạn ---
def get_or_create_rsa_keys(password: str):
    private_path = "private_key.pem"
    public_path = "public_key.pem"

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

# --- Giữ nguyên hàm mã hóa AES ---
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

# ================= CÁC API DÀNH CHO FRONTEND =================
@app.route('/api/encrypt', methods=['POST'])
def api_encrypt():
    # 1. Nhận dữ liệu từ web gửi lên
    uploaded_file = request.files['file']
    rsa_pass = request.form.get('rsa_pass', 'admin123') # Có thể làm ô nhập pass trên web sau
    n = int(request.form.get('n', 5)) # Tổng số thành viên
    k = int(request.form.get('k', 3)) # Số chữ ký cần để giải mã

    if uploaded_file.filename != '':
        os.makedirs("uploads", exist_ok=True)
        file_path = os.path.join("uploads", uploaded_file.filename)
        uploaded_file.save(file_path)

        # 2. Xử lý mã hóa như bạn đã viết
        priv_key, pub_key = get_or_create_rsa_keys(rsa_pass)
        raw_aes_key, enc_path = encrypt_file(file_path)
        
        session_salt = secrets.token_hex(4)
        combined_secret = raw_aes_key.hex() + ":" + session_salt

        encrypted_session_secret = pub_key.encrypt(
            combined_secret.encode(),
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )

        shares = PlaintextToHexSecretSharer.split_secret(encrypted_session_secret.hex(), k, n)

        # 3. Trả về kết quả chuẩn JSON cho file index.html
        return jsonify({
            "status": "success",
            "filename": os.path.basename(enc_path),
            "session_salt": session_salt,
            "shares": shares,
            "download_url": f"http://127.0.0.1:5000/download/{os.path.basename(enc_path)}"
        })
    return jsonify({"status": "error", "message": "Không có file"}), 400
if __name__ == '__main__':
    # Khi deploy, server sẽ cấp một cổng (PORT) ngẫu nhiên
    port = int(os.environ.get("PORT", 5000))
    # Host '0.0.0.0' để server có thể nhận kết nối từ bên ngoài (Netlify)
    app.run(host='0.0.0.0', port=port)
@app.route('/download/<filename>')
def download_file(filename):
    return send_file(os.path.join("uploads", filename), as_attachment=True)

if __name__ == '__main__':
    app.run(debug=True, port=5000)
