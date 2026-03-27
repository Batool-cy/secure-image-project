import os, numpy as np, matplotlib.pyplot as plt, hashlib, struct
from PIL import Image
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
import matplotlib

matplotlib.use('Agg')
UPLOAD_FOLDER = os.path.join('static', 'uploads')

# تثبيت الـ IV لضمان عدم الحاجة لإرساله بشكل منفصل
FIXED_IV = b'Batool_Secure_16'

# توليد مفاتيح RSA إذا لم تكن موجودة (تنفذ مرة واحدة فقط)
if not os.path.exists("private.pem"):
    key = RSA.generate(2048)
    with open("private.pem", "wb") as f: f.write(key.export_key())
    with open("public.pem", "wb") as f: f.write(key.publickey().export_key())


def calculate_entropy(img_path):
    try:
        with open(img_path, 'rb') as f:
            data = np.frombuffer(f.read(), dtype=np.uint8)
        probs = np.bincount(data, minlength=256) / len(data)
        probs = probs[probs > 0]
        return round(-np.sum(probs * np.log2(probs)), 4)
    except:
        return 0.0


def generate_histogram(img_path, output_name):
    try:
        with open(img_path, 'rb') as f:
            data = np.frombuffer(f.read(), dtype=np.uint8)
        plt.figure(figsize=(4, 2))
        plt.hist(data, bins=256, color='#00d4ff', alpha=0.7)
        plt.axis('off')
        plt.savefig(os.path.join(UPLOAD_FOLDER, output_name), bbox_inches='tight', transparent=True)
        plt.close()
        return output_name
    except:
        return None


def encrypt_image(input_path, user_key):
    img = Image.open(input_path).convert('RGB')
    w, h = img.size
    img_data = np.array(img).tobytes()

    # 1. تشفير AES للمحتوى
    aes_key = hashlib.sha256(user_key.strip().encode()).digest()
    cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv=FIXED_IV)
    enc_img_bytes = cipher_aes.encrypt(pad(img_data, AES.block_size))

    # 2. تشفير مفتاح AES باستخدام RSA (Public Key)
    pub_key = RSA.import_key(open("public.pem").read())
    cipher_rsa = PKCS1_OAEP.new(pub_key)
    enc_aes_key = cipher_rsa.encrypt(aes_key)

    # 3. بناء ملف الـ .bin: [طول المفتاح + المفتاح المشفر + الأبعاد + البيانات المشفرة]
    header = struct.pack('I', len(enc_aes_key)) + enc_aes_key + struct.pack('II', w, h)
    enc_filename = "enc_" + os.path.basename(input_path).split('.')[0] + ".bin"

    with open(os.path.join(UPLOAD_FOLDER, enc_filename), "wb") as f:
        f.write(header + enc_img_bytes)

    # توليد صورة الضوضاء (Noise Preview)
    preview_name = "preview_" + os.path.basename(input_path).split('.')[0] + ".png"
    Image.fromarray(np.random.randint(0, 256, (h, w, 3), dtype=np.uint8)).save(
        os.path.join(UPLOAD_FOLDER, preview_name))
    return enc_filename, preview_name


def decrypt_image(enc_filename, user_key):
    try:
        path = os.path.join(UPLOAD_FOLDER, enc_filename)
        with open(path, "rb") as f:
            k_len = struct.unpack('I', f.read(4))[0]
            enc_aes_key = f.read(k_len)
            w, h = struct.unpack('II', f.read(8))
            enc_img_bytes = f.read()

        # فك تشفير مفتاح AES باستخدام RSA (Private Key)
        priv_key = RSA.import_key(open("private.pem").read())
        dec_aes_key = PKCS1_OAEP.new(priv_key).decrypt(enc_aes_key)

        # التحقق من الباسورد (Access Token)
        if dec_aes_key != hashlib.sha256(user_key.strip().encode()).digest(): return None

        cipher_aes = AES.new(dec_aes_key, AES.MODE_CBC, iv=FIXED_IV)
        dec_bytes = unpad(cipher_aes.decrypt(enc_img_bytes), AES.block_size)

        dec_img = Image.frombytes('RGB', (w, h), dec_bytes)
        dec_name = "dec_" + enc_filename.replace(".bin", ".png")
        dec_img.save(os.path.join(UPLOAD_FOLDER, dec_name))
        return dec_name
    except:
        return None