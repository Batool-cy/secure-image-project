from flask import Flask, render_template, request, jsonify, send_from_directory, os
import base64
from encryption_logic import encrypt_image, decrypt_image, calculate_entropy, generate_histogram

app = Flask(__name__)
UPLOAD_FOLDER = os.path.join('static', 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def get_image_base64(filename):
    try:
        path = os.path.join(UPLOAD_FOLDER, filename)
        if os.path.exists(path):
            with open(path, "rb") as img_file:
                return base64.b64encode(img_file.read()).decode('utf-8')
    except: pass
    return ""

@app.route('/')
def index(): return render_template('index.html')

@app.route('/receiver_upload', methods=['POST'])
def receiver_upload():
    file = request.files.get('file')
    key = request.form.get('key')
    if file:
        filename = file.filename
        file.save(os.path.join(UPLOAD_FOLDER, filename))
        preview_name = "preview_" + filename.replace("enc_", "").split('.')[0] + ".png"
        # نرسل الصورة كـ Base64 لكي تظهر فوراً
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

@app.route('/static/uploads/<filename>')
def send_upload(filename):
    return send_from_directory(UPLOAD_FOLDER, filename)

if __name__ == '__main__':
    app.run(debug=True)
