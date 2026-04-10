from flask import Flask, render_template, request, jsonify, send_from_directory, url_for
import os
import base64
from encryption_logic import encrypt_image, decrypt_image, calculate_entropy, generate_histogram

app = Flask(__name__)
# إعداد المجلدات
UPLOAD_FOLDER = os.path.join('static', 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

report_data = {}

# --- دالة حاسمة لتحويل الصورة إلى نص (Base64) لتعمل على السيرفر بدون خطأ 404 ---
def get_image_base64(filename):
    try:
        path = os.path.join(UPLOAD_FOLDER, filename)
        if os.path.exists(path):
            with open(path, "rb") as img_file:
                return base64.b64encode(img_file.read()).decode('utf-8')
    except Exception as e:
        print(f"Error encoding image: {e}")
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

    global report_data
    report_data = {
        'entropy': calculate_entropy(os.path.join(UPLOAD_FOLDER, enc_file)),
        'h_orig': generate_histogram(os.path.join(UPLOAD_FOLDER, orig_name), "h_orig.png"),
        'h_enc': generate_histogram(os.path.join(UPLOAD_FOLDER, enc_file), "h_enc.png")
    }
    
    # نرسل نص الصورة (Base64) بدلاً من الاسم فقط
    noise_data = get_image_base64(noise)
    return jsonify({'enc_file': enc_file, 'noise_preview': noise_data})

@app.route('/analysis')
def analysis():
    return render_template('report.html', **report_data)

@app.route('/receiver_upload', methods=['POST'])
def receiver_upload():
    file = request.files.get('file')
    key = request.form.get('key')
    if file:
        filename = file.filename
        file_save_path = os.path.join(UPLOAD_FOLDER, filename)
        file.save(file_save_path)
        
        # استنتاج اسم صورة النويز
        preview_name = "preview_" + filename.replace("enc_", "").split('.')[0] + ".png"
        
        # تحويل صورة المعاينة لنص Base64
        preview_data = get_image_base64(preview_name)
        
        return render_template('receiver_control.html', enc_file=filename, key=key, preview=preview_data)
    return "No file provided"

@app.route('/decrypt_action', methods=['POST'])
def decrypt_action():
    data = request.get_json()
    # فك التشفير
    dec_file_name = decrypt_image(os.path.join(UPLOAD_FOLDER, data['file']), data['key'])
    
    if dec_file_name:
        # تحويل النتيجة لنص Base64 لضمان عرضها
        dec_data = get_image_base64(dec_file_name)
        return jsonify({'dec_file': dec_data})
    
    return jsonify({'error': 'Unauthorized/Wrong Key'}), 401

@app.route('/static/uploads/<filename>')
def send_upload(filename):
    return send_from_directory(UPLOAD_FOLDER, filename)

if __name__ == '__main__':
    app.run(debug=True, port=5000)
