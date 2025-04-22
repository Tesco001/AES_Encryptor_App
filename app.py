from flask import Flask, render_template, request, send_from_directory
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
import os
from werkzeug.utils import secure_filename

app = Flask(__name__)
UPLOAD_FOLDER = 'static/uploads'
DOWNLOAD_FOLDER = 'static/downloads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(DOWNLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['DOWNLOAD_FOLDER'] = DOWNLOAD_FOLDER

key = b'ThisIsASecretKey'
iv = b'ThisIsAnInitVect'

def encrypt_text(text):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_data = pad(text.encode(), AES.block_size)
    encrypted = cipher.encrypt(padded_data)
    return base64.b64encode(encrypted).decode()

def decrypt_text(cipher_text):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decoded = base64.b64decode(cipher_text)
    decrypted = cipher.decrypt(decoded)
    return unpad(decrypted, AES.block_size).decode()

def encrypt_file(data):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded = pad(data, AES.block_size)
    return cipher.encrypt(padded)

def decrypt_file(data):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(data)
    return unpad(decrypted, AES.block_size)

@app.route('/', methods=['GET', 'POST'])
def index():
    result = ""
    input_text = ""
    mode = "Encrypt"
    download_url = None

    if request.method == 'POST':
        if 'text' in request.form:
            input_text = request.form['text']
            mode = request.form['mode']

            try:
                if mode == 'Encrypt':
                    result = encrypt_text(input_text)
                else:
                    result = decrypt_text(input_text)
            except Exception as e:
                result = f"❌ Error: {str(e)}"

    return render_template('index.html', result=result, input_text=input_text, mode=mode, download_url=download_url)

@app.route('/file', methods=['POST'])
def handle_file():
    file = request.files['file']
    mode = request.form['mode']
    filename = secure_filename(file.filename)
    upload_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(upload_path)

    with open(upload_path, 'rb') as f:
        file_data = f.read()

    try:
        if mode == 'Encrypt':
            processed_data = encrypt_file(file_data)
            output_filename = f'encrypted_{filename}.enc'
        else:
            processed_data = decrypt_file(file_data)
            output_filename = f'decrypted_{filename}'

        output_path = os.path.join(app.config['DOWNLOAD_FOLDER'], output_filename)
        with open(output_path, 'wb') as f:
            f.write(processed_data)

        return render_template('index.html', result=None, input_text=None, mode=mode, download_url=f'/download/{output_filename}')
    except Exception as e:
        return render_template('index.html', result=f"❌ Error: {str(e)}", input_text=None, mode=mode)

@app.route('/download/<filename>')
def download_file(filename):
    return send_from_directory(app.config['DOWNLOAD_FOLDER'], filename, as_attachment=True)

if __name__ == '__main__':
    app.run(debug=True)
