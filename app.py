import os
import base64
from flask import Flask, render_template, request, jsonify, send_from_directory

app = Flask(__name__)

# إعداد المجلدات بصيغة Linux
UPLOAD_FOLDER = os.path.join('static', 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# استيراد الدوال مع معالجة الخطأ
try:
    from encryption_logic import encrypt_image, decrypt_image, calculate_entropy, generate_histogram
except ImportError as e:
    print(f"Import Error: {e}")

def get_image_base64(filename):
    try:
        path = os.path.join(UPLOAD_FOLDER, filename)
        if os.path.exists(path):
            with open(path, "rb") as img_file:
                return base64.b64encode(img_file.read()).decode('utf-8')
    except:
        pass
    return ""

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/sender_panel')
def sender_panel():
    return render_template('sender.html')

@app.route('/receiver_panel')
def receiver_panel():
    return render_template('receiver.html')

@app.route('/encrypt_start', methods=['POST'])
def encrypt_start():
    file = request.files.get('image')
    key = request.form.get('key')
    if file:
        filename = file.filename
        file_path = os.path.join(UPLOAD_FOLDER, filename)
        file.save(file_path)
        return render_template('sender.html', orig=filename, key=key)
    return "No file uploaded"

@app.route('/encrypt_action', methods=['POST'])
def encrypt_action():
    data = request.get_json()
    orig_name = data['file']
    user_key = data['key']
    
    # تنفيذ التشفير
    enc_file, noise = encrypt_image(os.path.join(UPLOAD_FOLDER, orig_name), user_key)
    
    # نرسل نص الصورة (Base64)
    noise_data = get_image_base64(noise)
    return jsonify({'enc_file': enc_file, 'noise_preview': noise_data})

@app.route('/receiver_upload', methods=['POST'])
def receiver_upload():
    file = request.files.get('file')
    key = request.form.get('key')
    if file:
        filename = file.filename
        file.save(os.path.join(UPLOAD_FOLDER, filename))
        preview_name = "preview_" + filename.replace("enc_", "").split('.')[0] + ".png"
        preview_data = get_image_base64(preview_name)
        return render_template('receiver_control.html', enc_file=filename, key=key, preview=preview_data)
    return "Error"

@app.route('/decrypt_action', methods=['POST'])
def decrypt_action():
    data = request.get_json()
    dec_file_name = decrypt_image(os.path.join(UPLOAD_FOLDER, data['file']), data['key'])
    if dec_file_name:
        return jsonify({'dec_file': get_image_base64(dec_file_name)})
    return jsonify({'error': 'Wrong Key'}), 401

if __name__ == '__main__':
    app.run(debug=True)
