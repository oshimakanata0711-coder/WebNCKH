# --- 5. API Giải mã ---
@app.route('/api/decrypt', methods=['POST'])
def api_decrypt():
    # Nhận dữ liệu từ Frontend
    if 'file' not in request.files:
        return jsonify({"status": "error", "message": "Thiếu file .enc"}), 400
    
    uploaded_file = request.files['file']
    shares = request.form.getlist('shares') # Danh sách các mảnh share (ít nhất là k mảnh)
    rsa_pass = request.form.get('rsa_pass', 'admin123')

    if len(shares) == 0:
        return jsonify({"status": "error", "message": "Thiếu các mảnh share"}), 400

    try:
        # 1. Lưu file .enc tạm thời
        enc_path = os.path.join(UPLOAD_FOLDER, "temp_" + uploaded_file.filename)
        uploaded_file.save(enc_path)

        # 2. Khôi phục chuỗi bí mật từ các mảnh shares (Shamir Recovery)
        recovered_hex_secret = PlaintextToHexSecretSharer.recover_secret(shares)

        # 3. Giải mã RSA để lấy lại AES Key và Salt
        priv_key, _ = get_or_create_rsa_keys(rsa_pass)
        
        decrypted_combined = priv_key.decrypt(
            bytes.fromhex(recovered_hex_secret),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()), 
                algorithm=hashes.SHA256(), 
                label=None
            )
        ).decode()

        # Tách AES Key và Salt (Chuỗi gốc là hex_aes:salt)
        raw_aes_key_hex, session_salt = decrypted_combined.split(":")
        aes_key = bytes.fromhex(raw_aes_key_hex)

        # 4. Giải mã File bằng AES
        with open(enc_path, 'rb') as f:
            iv_plus_data = f.read()
            iv = iv_plus_data[:16]
            encrypted_data = iv_plus_data[16:]

        cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        original_data = decryptor.update(encrypted_data) + decryptor.finalize()

        # 5. Lưu file đã giải mã và trả về
        dec_filename = uploaded_file.filename.replace(".enc", "")
        dec_path = os.path.join(UPLOAD_FOLDER, "decrypted_" + dec_filename)
        with open(dec_path, 'wb') as f:
            f.write(original_data)

        return jsonify({
            "status": "success",
            "message": "Giải mã thành công",
            "download_url": f"{request.host_url}download/{os.path.basename(dec_path)}"
        })

    except Exception as e:
        return jsonify({"status": "error", "message": f"Lỗi giải mã: {str(e)}"}), 500
