from flask import Flask, render_template, request, jsonify, send_from_directory
import os
from encryption_logic import encrypt_image, decrypt_image, calculate_entropy, generate_histogram

app = Flask(__name__)
UPLOAD_FOLDER = os.path.join('static', 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# مخزن مؤقت لبيانات التقرير الإحصائي
report_data = {}


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
        file.save(os.path.join(UPLOAD_FOLDER, filename))
        return render_template('sender.html', orig=filename, key=key)
    return "No file uploaded"


@app.route('/encrypt_action', methods=['POST'])
def encrypt_action():
    data = request.get_json()
    orig_name = data['file']
    user_key = data['key']

    # تنفيذ التشفير الهجين
    enc_file, noise = encrypt_image(os.path.join(UPLOAD_FOLDER, orig_name), user_key)

    # إعداد بيانات التقرير (الهيستوجرام والإنتروبي)
    global report_data
    report_data = {
        'entropy': calculate_entropy(os.path.join(UPLOAD_FOLDER, enc_file)),
        'h_orig': generate_histogram(os.path.join(UPLOAD_FOLDER, orig_name), "h_orig.png"),
        'h_enc': generate_histogram(os.path.join(UPLOAD_FOLDER, enc_file), "h_enc.png")
    }
    return jsonify({'enc_file': enc_file, 'noise_preview': noise})


@app.route('/analysis')
def analysis():
    return render_template('report.html', **report_data)


@app.route('/receiver_upload', methods=['POST'])
def receiver_upload():
    file = request.files.get('file')
    key = request.form.get('key')
    if file:
        filename = file.filename
        file.save(os.path.join(UPLOAD_FOLDER, filename))
        # استنتاج اسم صورة النويز للمعاينة
        preview = "preview_" + filename.replace("enc_", "").split('.')[0] + ".png"
        return render_template('receiver_control.html', enc_file=filename, key=key, preview=preview)
    return "No file provided"


@app.route('/decrypt_action', methods=['POST'])
def decrypt_action():
    data = request.get_json()
    dec_file = decrypt_image(data['file'], data['key'])
    if dec_file:
        return jsonify({'dec_file': dec_file})
    return jsonify({'error': 'Unauthorized/Wrong Key'}), 401


@app.route('/download/<filename>')
def download(filename):
    return send_from_directory(UPLOAD_FOLDER, filename)


if __name__ == '__main__':
    app.run(debug=True, port=5000)
