from flask import Flask, render_template, request, jsonify, send_from_directory
import os, base64
import time
from encryption_logic import *

app = Flask(__name__)
UPLOAD_FOLDER = os.path.join('static', 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# مخزن البيانات - تم التأكد من مسميات المفاتيح لتطابق الداشبورد
report_data = {
    'orig_entropy': 0, 'enc_entropy': 0, 'dec_entropy': 0,
    'enc_npcr': 0, 'enc_uaci': 0,
    'dec_npcr': 0, 'dec_uaci': 0,
    'orig_img': '', 'enc_img': '', 'dec_img': '',
    'h_orig': '', 'h_enc': '',

     'aes_enc_time': 0, 'aes_dec_time': 0,
    'rsa_enc_time': 0, 'rsa_dec_time': 0,
    'total_enc_time': 0, 'total_dec_time': 0

}

@app.route('/')
def index(): return render_template('index.html')

@app.route('/sender_panel')
def sender_panel(): return render_template('sender.html')

@app.route('/analysis')
def analysis():
    global report_data
    # تأكدي أن اسم الملف هنا هو report.html وموجود في مجلد templates
    return render_template('report.html', **report_data)

@app.route('/encrypt_start', methods=['POST'])
def encrypt_start():
    file = request.files.get('image')
    key = request.form.get('key')
    if file:
        filename = file.filename.replace(" ", "_")
        file.save(os.path.join(UPLOAD_FOLDER, filename))
        return render_template('sender.html', orig=filename, key=key)
    return "No file uploaded"


@app.route('/encrypt_action', methods=['POST'])
def encrypt_action():
    global report_data
    data = request.get_json()
    orig_name, user_key = data['file'], data['key']
    path_orig = os.path.join(UPLOAD_FOLDER, orig_name)

    # 1. تنفيذ التشفير (استقبال 4 قيم بدلاً من 2)
    enc_file, noise, aes_t, rsa_t = encrypt_image(path_orig, user_key)

    # 2. حساب الحساسية (بمفتاح مختلف قليلاً)
    # ملاحظة: سنستخدم الـ _ لتجاهل الأوقات هنا لأننا لا نحتاجها في اختبار الحساسية
    diff_key = user_key + "1"
    enc_file2, _, _, _ = encrypt_image(path_orig, diff_key)

    p1 = os.path.join(UPLOAD_FOLDER, enc_file)
    p2 = os.path.join(UPLOAD_FOLDER, enc_file2)

    # 3. حساب القيم الإحصائية
    npcr_val, uaci_val = calculate_npcr_uaci(p1, p2)
    entropy_val = calculate_entropy(p1)
    orig_ent = calculate_entropy(path_orig)

    # 4. التحديث (تخزين القيم الإحصائية + قيم الوقت الجديدة)
    report_data['enc_npcr'] = round(npcr_val, 4)
    report_data['enc_uaci'] = round(uaci_val, 4)
    report_data['enc_entropy'] = round(entropy_val, 4)
    report_data['orig_entropy'] = round(orig_ent, 4)
    report_data['orig_img'] = orig_name
    report_data['enc_img'] = enc_file

    # --- إضافة قيم الوقت للداشبورد ---
    report_data['aes_enc_time'] = round(aes_t, 6)
    report_data['rsa_enc_time'] = round(rsa_t, 6)
    report_data['total_enc_time'] = round(aes_t + rsa_t, 6)

    # 5. الهستوجرام
    report_data['h_orig'] = generate_histogram(path_orig, "h_orig.png")
    report_data['h_enc'] = generate_histogram(p1, "h_enc.png")

    return jsonify({
        'status': 'success',
        'enc_file': enc_file,
        'noise_preview': noise,
        'npcr': npcr_val,
        'uaci': uaci_val
    })


@app.route('/receiver_upload', methods=['POST'])
def receiver_upload():
    global report_data
    file = request.files.get('file')
    key = request.form.get('key')
    if file:
        filename = file.filename.replace(" ", "_")
        file.save(os.path.join(UPLOAD_FOLDER, filename))
        report_data['enc_img'] = filename
        preview = "preview_" + filename.replace("enc_", "").split('.')[0] + ".png"
        return render_template('receiver_control.html', enc_file=filename, key=key, preview=preview, **report_data)
    return "Error"

@app.route('/decrypt_action', methods=['POST'])
def decrypt_action():
    import base64, traceback
    global report_data
    try:
        data = request.get_json()
        filename = data.get('file')
        user_key = data.get('key')

        if not filename or not user_key:
            return jsonify({'error': 'بيانات ناقصة'}), 400

        # التعديل هنا: استقبال اسم الملف + وقت RSA + وقت AES
        dec_file_name, r_time, a_time = decrypt_image(filename, user_key.strip())

        if dec_file_name:
            # إضافة البيانات الجديدة لمخزن التقرير (Dashboard)
            report_data['dec_img'] = dec_file_name
            report_data['rsa_dec_time'] = round(r_time, 6)
            report_data['aes_dec_time'] = round(a_time, 6)
            report_data['total_dec_time'] = round(r_time + a_time, 6)

            dec_full_path = os.path.join(UPLOAD_FOLDER, dec_file_name)
            with open(dec_full_path, "rb") as img_file:
                return jsonify({'dec_file': base64.b64encode(img_file.read()).decode('utf-8')})

        return jsonify({'error': 'فشلت عملية فك التشفير'}), 401
    except Exception as e:
        return jsonify({'error': traceback.format_exc()}), 500

@app.route('/receiver_analysis_action', methods=['POST'])
def receiver_analysis_action():
    global report_data
    path_orig = os.path.join(UPLOAD_FOLDER, report_data.get('orig_img', ''))
    path_dec = os.path.join(UPLOAD_FOLDER, report_data.get('dec_img', ''))

    if os.path.exists(path_orig) and os.path.exists(path_dec):
        d_npcr, d_uaci = calculate_fidelity_metrics(path_orig, path_dec)
        report_data['dec_npcr'] = d_npcr
        report_data['dec_uaci'] = d_uaci
        report_data['dec_entropy'] = calculate_entropy(path_dec)
        return jsonify({'status': 'success'})
    return jsonify({'error': 'Files missing'}), 400

@app.route('/receiver_analysis_page')
def receiver_analysis_page():
    return render_template('receiver_analysis.html', **report_data)

@app.route('/dashboard')
def dashboard(): return render_template('dashboard.html', **report_data)

@app.route('/receiver_panel')
def receiver_panel():
    return render_template('receiver.html')

@app.route('/download/<filename>')
def download(filename): return send_from_directory(UPLOAD_FOLDER, filename)

if __name__ == '__main__': app.run(debug=True, port=5000)
