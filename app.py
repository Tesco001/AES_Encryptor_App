import os
from flask import Flask, render_template, request, send_file
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['PROCESSED_FOLDER'] = 'processed'

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['PROCESSED_FOLDER'], exist_ok=True)

key = b'ThisIsASecretKey1234567890123456'  # 32 bytes for AES-256
iv = b'ThisIsAnInitVect'  # 16 bytes

# --- Text Encryption ---
def encrypt_text(plain_text):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded = pad(plain_text.encode(), AES.block_size)
    encrypted = cipher.encrypt(padded)
    return base64.b64encode(encrypted).decode()

# --- Text Decryption ---
def decrypt_text(cipher_text):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decoded = base64.b64decode(cipher_text)
    decrypted = unpad(cipher.decrypt(decoded), AES.block_size)
    return decrypted.decode()

# --- File Encryption ---
def encrypt_file(file_data, filename):
    ext = os.path.splitext(filename)[1]
    prefix = f"{ext}::EXT::".encode()
    data_with_ext = prefix + file_data

    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded = pad(data_with_ext, AES.block_size)
    encrypted = cipher.encrypt(padded)
    return encrypted

# --- File Decryption ---
def decrypt_file(encrypted_data):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(encrypted_data), AES.block_size)

    try:
        ext_marker = b'::EXT::'
        ext_index = decrypted.find(ext_marker)
        if ext_index == -1:
            raise ValueError("Extension marker not found.")
        ext = decrypted[:ext_index].decode()
        content = decrypted[ext_index + len(ext_marker):]
        return ext, content
    except Exception as e:
        raise ValueError("Invalid decryption format") from e

@app.route('/', methods=['GET', 'POST'])
def text_encrypt_decrypt():
    result = ""
    input_text = ""
    mode = "Encrypt"

    if request.method == 'POST':
        input_text = request.form['text']
        mode = request.form['mode']
        try:
            if mode == 'Encrypt':
                result = encrypt_text(input_text)
            else:
                result = decrypt_text(input_text)
        except Exception as e:
            result = f"❌ Error: {str(e)}"

    return render_template('index.html', result=result, input_text=input_text, mode=mode)

@app.route('/file', methods=['GET', 'POST'])
def handle_file():
    result_file = None
    operation = None

    if request.method == 'POST':
        file = request.files['file']
        operation = request.form['mode']
        filename = secure_filename(file.filename)

        if file and operation == 'Encrypt':
            file_data = file.read()
            encrypted_data = encrypt_file(file_data, filename)
            output_path = os.path.join(app.config['PROCESSED_FOLDER'], filename + '.enc')
            with open(output_path, 'wb') as f:
                f.write(encrypted_data)
            result_file = output_path

        elif file and operation == 'Decrypt':
            file_data = file.read()
            try:
                ext, decrypted_data = decrypt_file(file_data)
                output_name = filename.replace('.enc', '') + ext
                output_path = os.path.join(app.config['PROCESSED_FOLDER'], output_name)
                with open(output_path, 'wb') as f:
                    f.write(decrypted_data)
                result_file = output_path
            except Exception as e:
                result_file = f"❌ Error: {str(e)}"

    return render_template('file.html', result_file=result_file, operation=operation)

@app.route('/download/<filename>')
def download_file(filename):
    file_path = os.path.join(app.config['PROCESSED_FOLDER'], filename)
    return send_file(file_path, as_attachment=True)

if __name__ == '__main__':
    app.run(debug=True)
