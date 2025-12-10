# app.py
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file, jsonify
import sqlite3, os, bcrypt, requests, wave, time
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from reportlab.pdfgen import canvas
import config
import base64
import cv2
import numpy as np
import sounddevice as sd
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import secrets
import string
import socket

# ==========================================
# 🔐 CIFRADO RSA + AES PARA LA SESIÓN
# ==========================================
try:
    SERVER_PRIVATE_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    SERVER_PUBLIC_KEY = SERVER_PRIVATE_KEY.public_key()
except Exception:
    SERVER_PRIVATE_KEY = None
    SERVER_PUBLIC_KEY = None

def generar_clave_aes():
    return os.urandom(32)

def cifrar_aes(clave, texto_plano):
    try:
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(clave), modes.CBC(iv))
        encryptor = cipher.encryptor()
        padder = sym_padding.PKCS7(128).padder()
        padded_data = padder.update(texto_plano.encode()) + padder.finalize()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        return iv + ciphertext
    except Exception:
        return texto_plano.encode()

def descifrar_aes(clave, ciphertext):
    try:
        if len(ciphertext) <= 16:
            return ciphertext.decode() if isinstance(ciphertext, bytes) else ciphertext
        
        iv = ciphertext[:16]
        ct = ciphertext[16:]
        cipher = Cipher(algorithms.AES(clave), modes.CBC(iv))
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(ct) + decryptor.finalize()
        unpadder = sym_padding.PKCS7(128).unpadder()
        data = unpadder.update(padded_data) + unpadder.finalize()
        return data.decode()
    except Exception:
        return ciphertext.decode() if isinstance(ciphertext, bytes) else ciphertext

def cifrar_clave_aes_rsa(clave_aes):
    if SERVER_PUBLIC_KEY is None:
        return clave_aes
    try:
        return SERVER_PUBLIC_KEY.encrypt(
            clave_aes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    except Exception:
        return clave_aes

def descifrar_clave_aes_rsa(clave_cifrada):
    if SERVER_PRIVATE_KEY is None:
        return clave_cifrada
    try:
        return SERVER_PRIVATE_KEY.decrypt(
            clave_cifrada,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    except Exception:
        return clave_cifrada

# ==========================================
# 🚀 INICIALIZAR LA APLICACIÓN
# ==========================================
app = Flask(__name__)

try:
    config.init_app_config(app)
except Exception as e:
    print(f"⚠️  Configuración no cargada: {e}")

app.secret_key = getattr(config, "SECRET_KEY", os.urandom(24))

# ==========================================
# 💾 RUTAS Y DIRECTORIOS
# ==========================================
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_FOLDER = os.path.join(BASE_DIR, "database")
os.makedirs(DB_FOLDER, exist_ok=True)
BIOMETRIC_FOLDER = os.path.join(BASE_DIR, "biometric_data")
os.makedirs(BIOMETRIC_FOLDER, exist_ok=True)

TEMPLATES_FOLDER = os.path.join(BIOMETRIC_FOLDER, "templates")
os.makedirs(TEMPLATES_FOLDER, exist_ok=True)

if not getattr(config, "UPLOAD_FOLDER", None):
    config.UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
os.makedirs(config.UPLOAD_FOLDER, exist_ok=True)

# ==========================================
# 💾 CONEXIÓN A LA BASE DE DATOS
# ==========================================
def conectar_db():
    db_path = getattr(config, "DATABASE_PATH", os.path.join(DB_FOLDER, "app.db"))
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn

# ==========================================
# 🔧 INICIALIZAR/ACTUALIZAR ESQUEMA
# ==========================================
def inicializar_bd():
    os.makedirs(DB_FOLDER, exist_ok=True)
    conn = conectar_db()
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS usuarios (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nombre TEXT,
        correo TEXT UNIQUE NOT NULL,
        password BLOB NOT NULL,
        face_path TEXT,
        voice_path TEXT,
        fecha_registro DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS medicamentos (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nombre TEXT NOT NULL,
        descripcion TEXT,
        dosis TEXT,
        frecuencia TEXT
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS recuperacion_contraseña (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        correo TEXT NOT NULL,
        token TEXT UNIQUE NOT NULL,
        fecha_creacion DATETIME DEFAULT CURRENT_TIMESTAMP,
        usado BOOLEAN DEFAULT FALSE
    )
    """)

    cur.execute("SELECT COUNT(*) FROM medicamentos")
    if cur.fetchone()[0] == 0:
        meds = [
            ("Metformina", "Reduce producción de glucosa.", "850 mg", "2 veces al día"),
            ("Insulina Glargina", "Insulina prolongada.", "10 unidades", "1 vez al día"),
            ("Glibenclamida", "Estimula liberación de insulina.", "5 mg", "1 vez al día"),
        ]
        cur.executemany("INSERT INTO medicamentos (nombre, descripcion, dosis, frecuencia) VALUES (?, ?, ?, ?)", meds)

    conn.commit()
    conn.close()

# ==========================================
# 🔐 FUNCIONES PARA RECUPERACIÓN DE CONTRASEÑA
# ==========================================
def generar_token_recuperacion(longitud=32):
    caracteres = string.ascii_letters + string.digits
    return ''.join(secrets.choice(caracteres) for _ in range(longitud))

def enviar_correo_recuperacion(destinatario, token):
    try:
        mensaje = MIMEMultipart()
        mensaje['From'] = getattr(config, "EMAIL_FROM", "no-reply@glucocontrol.com")
        mensaje['To'] = destinatario
        mensaje['Subject'] = "Recuperación de Contraseña - Glucocontrol Seguro"
        
        host = getattr(config, "HOST", "localhost")
        port = getattr(config, "PORT", 5000)
        base_url = getattr(config, "BASE_URL", f"http://{host}:{port}")
        url_recuperacion = f"{base_url}/reset-password/{token}"

        cuerpo = f"""
        <html>
        <body>
            <h2>Recuperación de Contraseña</h2>
            <p>Has solicitado restablecer tu contraseña en Glucocontrol Seguro.</p>
            <p>Para crear una nueva contraseña, haz clic en el siguiente enlace:</p>
            <p><a href="{url_recuperacion}" style="background-color: #4CAF50; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Restablecer Contraseña</a></p>
            <p>Este enlace expirará en 1 hora.</p>
            <p>Si no solicitaste este cambio, ignora este mensaje.</p>
            <br>
            <p><strong>Sistema Glucocontrol Seguro</strong></p>
        </body>
        </html>
        """

        mensaje.attach(MIMEText(cuerpo, 'html'))

        email_host = getattr(config, "EMAIL_HOST", "localhost")
        email_port = getattr(config, "EMAIL_PORT", 587)
        
        with smtplib.SMTP(email_host, email_port, timeout=10) as server:
            if email_port == 587:
                server.starttls()
            
            email_user = getattr(config, "EMAIL_USER", None)
            email_password = getattr(config, "EMAIL_PASSWORD", None)
            if email_user and email_password:
                server.login(email_user, email_password)
            
            server.send_message(mensaje)

        return True
    except Exception as e:
        print(f"❌ Error enviando correo: {e}")
        return False

# ==========================================
# 🧱 FUNCIONES AUXILIARES
# ==========================================
def allowed_file(filename):
    allowed_extensions = getattr(config, "ALLOWED_EXTENSIONS", {"pdf", "png", "jpg", "jpeg", "txt", "wav"})
    return "." in filename and filename.rsplit(".", 1)[1].lower() in allowed_extensions

def verificar_recaptcha(response_token):
    secret = getattr(config, "RECAPTCHA_SECRET_KEY", None)
    if not secret:
        return True
    url = "https://www.google.com/recaptcha/api/siteverify"
    data = {
        "secret": secret,
        "response": response_token
    }
    try:
        r = requests.post(url, data=data, timeout=5)
        return r.json().get("success", False)
    except Exception as e:
        print(f"❌ Error verificando reCAPTCHA: {e}")
        return False

# ==========================================
# 👤 FUNCIONES BIOMÉTRICAS MEJORADAS
# ==========================================
try:
    FACE_CASCADE = cv2.CascadeClassifier(cv2.data.haarcascades + "haarcascade_frontalface_default.xml")
except Exception:
    FACE_CASCADE = None
    print("⚠️  No se pudo cargar el clasificador de rostros")

def _face_filename_for(correo, prefix="face"):
    safe = correo.replace("@","_").replace(".","_")
    ts = int(time.time())
    return os.path.join(BIOMETRIC_FOLDER, f"{prefix}_{safe}_{ts}.jpg")

def _voice_filename_for(correo, prefix="voice"):
    safe = correo.replace("@","_").replace(".","_")
    ts = int(time.time())
    return os.path.join(BIOMETRIC_FOLDER, f"{prefix}_{safe}_{ts}.wav")

def _face_template_path(correo):
    safe = correo.replace("@","_").replace(".","_")
    return os.path.join(TEMPLATES_FOLDER, f"face_template_{safe}.npy")

def _voice_template_path(correo):
    safe = correo.replace("@","_").replace(".","_")
    return os.path.join(TEMPLATES_FOLDER, f"voice_template_{safe}.npy")

def capture_face_image(correo=None, prefix="face"):
    """Captura una imagen desde la cámara y detecta rostros - VERSIÓN MEJORADA"""
    if FACE_CASCADE is None:
        print("❌ Clasificador de rostros no disponible")
        return None
        
    try:
        # Intentar diferentes backends de cámara
        backends = [
            cv2.CAP_DSHOW,  # Windows DirectShow
            cv2.CAP_ANY     # Cualquier backend disponible
        ]
        
        cam = None
        for backend in backends:
            try:
                cam = cv2.VideoCapture(0, backend)
                if cam.isOpened():
                    print(f"✅ Cámara abierta con backend: {backend}")
                    break
                else:
                    cam = None
            except Exception as e:
                print(f"⚠️ Error con backend {backend}: {e}")
                continue
        
        if cam is None:
            # Intentar método tradicional como fallback
            try:
                cam = cv2.VideoCapture(0)
                if not cam.isOpened():
                    cam = cv2.VideoCapture(0, cv2.CAP_DSHOW)
            except Exception as e:
                print(f"❌ Error abriendo cámara: {e}")
                
        if cam is None or not cam.isOpened():
            print("❌ No se pudo abrir la cámara con ningún método")
            return None

        # Configurar resolución
        cam.set(cv2.CAP_PROP_FRAME_WIDTH, 640)
        cam.set(cv2.CAP_PROP_FRAME_HEIGHT, 480)
        cam.set(cv2.CAP_PROP_FPS, 30)
        
        # Dar tiempo a la cámara para inicializar
        print("📷 Inicializando cámara...")
        time.sleep(2)
        
        # Capturar múltiples frames y usar el mejor
        best_frame = None
        max_faces = 0
        
        for i in range(5):  # Capturar 5 frames
            ret, frame = cam.read()
            if not ret or frame is None:
                continue
                
            # Detectar rostros
            gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
            faces = FACE_CASCADE.detectMultiScale(
                gray, 
                scaleFactor=1.1, 
                minNeighbors=5, 
                minSize=(100, 100)
            )
            
            print(f"📸 Frame {i+1}: {len(faces)} rostros detectados")
            
            if len(faces) > max_faces:
                max_faces = len(faces)
                best_frame = frame.copy()
                
            time.sleep(0.1)  # Pequeña pausa entre frames
        
        cam.release()
        
        if best_frame is None:
            print("❌ No se pudo capturar ningún frame válido")
            return None

        # Procesar el mejor frame
        gray = cv2.cvtColor(best_frame, cv2.COLOR_BGR2GRAY)
        faces = FACE_CASCADE.detectMultiScale(
            gray, 
            scaleFactor=1.1, 
            minNeighbors=5, 
            minSize=(100, 100)
        )

        if len(faces) == 0:
            print("❌ No se detectaron rostros en la imagen")
            return None

        # Generar nombre de archivo
        if correo:
            out_path = _face_filename_for(correo, prefix)
        else:
            out_path = os.path.join(BIOMETRIC_FOLDER, f"{prefix}_temp_{int(time.time())}.jpg")

        # Recortar y guardar el primer rostro detectado
        x, y, w, h = faces[0]
        # Añadir margen alrededor del rostro
        margin = 20
        x = max(0, x - margin)
        y = max(0, y - margin)
        w = min(best_frame.shape[1] - x, w + 2 * margin)
        h = min(best_frame.shape[0] - y, h + 2 * margin)
        
        face_img = best_frame[y:y+h, x:x+w]
        success = cv2.imwrite(out_path, face_img)
        
        if success:
            print(f"✅ Rostro detectado y guardado: {out_path}")
            return out_path
        else:
            print("❌ Error guardando imagen del rostro")
            return None
        
    except Exception as e:
        print(f"❌ Error capturando rostro: {e}")
        import traceback
        traceback.print_exc()
        return None

def build_face_template_from_image(path, size=(100, 100)):
    """Construye plantilla facial a partir de imagen"""
    try:
        img = cv2.imread(path)
        if img is None:
            print(f"❌ No se pudo cargar imagen: {path}")
            return None
            
        # Convertir a escala de grises y redimensionar
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        gray = cv2.resize(gray, size)
        
        # Aplicar equalización de histograma para mejorar contraste
        gray = cv2.equalizeHist(gray)
        
        # Convertir a vector y normalizar
        vec = gray.astype("float32").flatten()
        vec = (vec - np.mean(vec)) / (np.std(vec) + 1e-9)
        vec = vec / (np.linalg.norm(vec) + 1e-9)
        
        return vec
    except Exception as e:
        print(f"❌ Error construyendo plantilla facial: {e}")
        return None

def save_face_template(correo, image_path):
    """Guarda plantilla facial"""
    try:
        tpl = build_face_template_from_image(image_path)
        if tpl is None:
            return False
            
        template_path = _face_template_path(correo)
        np.save(template_path, tpl)
        print(f"✅ Plantilla facial guardada: {template_path}")
        return True
    except Exception as e:
        print(f"❌ Error guardando plantilla facial: {e}")
        return False

def load_face_template(correo):
    """Carga plantilla facial"""
    try:
        p = _face_template_path(correo)
        if os.path.exists(p):
            return np.load(p)
        else:
            print(f"⚠️  No existe plantilla para: {correo}")
    except Exception as e:
        print(f"❌ Error cargando plantilla facial: {e}")
    return None

def compare_face_templates(template1, template2):
    """Compara dos plantillas faciales usando similitud coseno"""
    if template1 is None or template2 is None:
        return 0.0, False
        
    try:
        # Asegurar que las plantillas tengan la misma dimensión
        min_len = min(len(template1), len(template2))
        template1 = template1[:min_len]
        template2 = template2[:min_len]
        
        # Calcular similitud coseno
        dot_product = np.dot(template1, template2)
        norm1 = np.linalg.norm(template1)
        norm2 = np.linalg.norm(template2)
        
        if norm1 == 0 or norm2 == 0:
            return 0.0, False
            
        similarity = dot_product / (norm1 * norm2)
        
        # Umbral ajustado
        threshold = 0.6
        matched = similarity > threshold
        
        print(f"🔍 Similitud facial: {similarity:.4f}, Umbral: {threshold}, Coincide: {matched}")
        return float(similarity), bool(matched)
    except Exception as e:
        print(f"❌ Error comparando plantillas: {e}")
        return 0.0, False

def record_audio(duration=3, sample_rate=16000):
    """Graba audio y lo guarda como WAV"""
    try:
        print("🎤 Iniciando grabación de audio...")
        audio_data = sd.rec(int(duration * sample_rate), 
                           samplerate=sample_rate, 
                           channels=1, 
                           dtype='int16')
        sd.wait()
        
        output_path = os.path.join(BIOMETRIC_FOLDER, f"temp_voice_{int(time.time())}.wav")
        
        with wave.open(output_path, 'wb') as wav_file:
            wav_file.setnchannels(1)
            wav_file.setsampwidth(2)
            wav_file.setframerate(sample_rate)
            wav_file.writeframes(audio_data.tobytes())
            
        print(f"✅ Audio grabado y guardado: {output_path}")
        return output_path
    except Exception as e:
        print(f"❌ Error grabando audio: {e}")
        return None

# ==========================================
# 🎥 NUEVAS FUNCIONES PARA CAPTURA DESDE CLIENTE
# ==========================================

def capture_face_from_request():
    """Captura rostro desde la solicitud HTTP (para login)"""
    try:
        if 'face_image' not in request.files:
            return None, "No se recibió imagen facial"
        
        file = request.files['face_image']
        if file.filename == '':
            return None, "Nombre de archivo vacío"
        
        # Guardar imagen temporal
        temp_path = os.path.join(BIOMETRIC_FOLDER, f"login_temp_{int(time.time())}.jpg")
        file.save(temp_path)
        
        # Verificar que sea una imagen válida
        img = cv2.imread(temp_path)
        if img is None:
            os.remove(temp_path)
            return None, "Imagen no válida"
        
        return temp_path, None
        
    except Exception as e:
        return None, f"Error procesando imagen: {str(e)}"

def procesar_imagen_para_comparacion(image_path):
    """Procesa imagen para comparación mejorada"""
    try:
        img = cv2.imread(image_path)
        if img is None:
            return None
            
        # Convertir a escala de grises
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        
        # Mejorar contraste
        gray = cv2.equalizeHist(gray)
        
        # Redimensionar a tamaño estándar
        gray = cv2.resize(gray, (100, 100))
        
        # Aplicar filtro Gaussiano para reducir ruido
        gray = cv2.GaussianBlur(gray, (3, 3), 0)
        
        # Convertir a vector y normalizar
        vec = gray.astype("float32").flatten()
        vec = (vec - np.mean(vec)) / (np.std(vec) + 1e-9)
        vec = vec / (np.linalg.norm(vec) + 1e-9)
        
        return vec
    except Exception as e:
        print(f"❌ Error procesando imagen: {e}")
        return None

# ==========================================
# 🔑 RUTAS PRINCIPALES
# ==========================================
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        nombre = request.form.get("nombre", "").strip()
        correo = request.form.get("correo", "").strip()
        password = request.form.get("password", "").strip()
        recaptcha_response = request.form.get("g-recaptcha-response", "")

        # Validaciones básicas
        if not all([nombre, correo, password]):
            flash("❌ Todos los campos son obligatorios", "error")
            return redirect(url_for("register"))

        if not verificar_recaptcha(recaptcha_response):
            flash("⚠️ Verifica el reCAPTCHA", "error")
            return redirect(url_for("register"))

        conn = conectar_db()
        cur = conn.cursor()
        
        # Verificar si el correo ya existe
        cur.execute("SELECT id FROM usuarios WHERE correo = ?", (correo,))
        if cur.fetchone():
            flash("⚠️ El correo ya está registrado", "error")
            conn.close()
            return redirect(url_for("register"))

        # Hash de la contraseña
        hashed_password = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
        
        # Insertar usuario sin datos biométricos inicialmente
        cur.execute("""
            INSERT INTO usuarios (nombre, correo, password, face_path, voice_path) 
            VALUES (?, ?, ?, ?, ?)
        """, (nombre, correo, hashed_password, None, None))
        
        user_id = cur.lastrowid
        conn.commit()

        # PROCESAR REGISTRO BIOMÉTRICO FACIAL
        face_path = None
        try:
            print("📷 Iniciando registro facial...")
            face_path = capture_face_image(correo, "register")
            if face_path:
                # Guardar plantilla facial
                if save_face_template(correo, face_path):
                    # Actualizar ruta en la base de datos
                    cur.execute("UPDATE usuarios SET face_path = ? WHERE id = ?", 
                               (face_path, user_id))
                    conn.commit()
                    print("✅ Registro facial completado exitosamente")
                    flash("✅ Registro exitoso con Face ID. Ya puedes iniciar sesión con tu rostro", "success")
                else:
                    print("❌ Error guardando plantilla facial")
                    flash("✅ Registro exitoso, pero no se pudo guardar Face ID. Usa correo y contraseña.", "success")
            else:
                print("❌ No se pudo capturar rostro para registro")
                flash("✅ Registro exitoso. Usa correo y contraseña para iniciar sesión", "success")
                
        except Exception as e:
            print(f"⚠️ Error en registro facial: {e}")
            flash("✅ Registro exitoso. Usa correo y contraseña para iniciar sesión", "success")

        conn.close()
        return redirect(url_for("login"))

    return render_template("register.html", 
                         site_key=getattr(config, "RECAPTCHA_SITE_KEY", ""))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        # Login tradicional con correo y contraseña
        correo = request.form.get("correo", "").strip()
        password = request.form.get("password", "").strip()
        recaptcha_response = request.form.get("g-recaptcha-response", "")

        if not all([correo, password]):
            flash("❌ Correo y contraseña son obligatorios", "error")
            return redirect(url_for("login"))

        if not verificar_recaptcha(recaptcha_response):
            flash("⚠️ Verifica el reCAPTCHA", "error")
            return redirect(url_for("login"))

        conn = conectar_db()
        cur = conn.cursor()
        
        # Buscar usuario
        cur.execute("""
            SELECT id, nombre, correo, password, face_path 
            FROM usuarios WHERE correo = ?
        """, (correo,))
        usuario = cur.fetchone()
        
        if not usuario:
            flash("❌ Credenciales incorrectas", "error")
            conn.close()
            return redirect(url_for("login"))

        # Verificar contraseña
        if not bcrypt.checkpw(password.encode("utf-8"), usuario["password"]):
            flash("❌ Credenciales incorrectas", "error")
            conn.close()
            return redirect(url_for("login"))

        # Iniciar sesión exitosa
        session["usuario_id"] = usuario["id"]
        session["usuario_nombre"] = usuario["nombre"]
        session["usuario_correo"] = usuario["correo"]
        
        # Generar clave de sesión segura
        clave_aes = generar_clave_aes()
        session["clave_aes_cifrada"] = cifrar_clave_aes_rsa(clave_aes)
        
        conn.close()
        flash(f"✅ Bienvenido/a {usuario['nombre']}", "success")
        return redirect(url_for("dashboard"))

    return render_template("login.html", 
                         site_key=getattr(config, "RECAPTCHA_SITE_KEY", ""))

# ==========================================
# 👤 RUTAS BIOMÉTRICAS PARA LOGIN CON FACE ID - VERSIÓN CORREGIDA
# ==========================================
@app.route("/verificar_rostro", methods=["POST"])
def verificar_rostro():
    """Verificación facial para login con Face ID - USA IMAGEN DEL CLIENTE"""
    try:
        print("🔍 Iniciando verificación facial para login...")
        
        # Verificar que el clasificador esté disponible
        if FACE_CASCADE is None:
            return jsonify({
                "success": False, 
                "error": "❌ Sistema de reconocimiento facial no disponible"
            })
        
        # Capturar rostro desde la solicitud del cliente
        current_face_path, error_msg = capture_face_from_request()
        if error_msg:
            return jsonify({
                "success": False, 
                "error": f"❌ {error_msg}"
            })

        # Buscar todos los usuarios registrados con Face ID
        conn = conectar_db()
        cur = conn.cursor()
        cur.execute("SELECT id, nombre, correo, face_path FROM usuarios WHERE face_path IS NOT NULL")
        usuarios = cur.fetchall()
        conn.close()

        if not usuarios:
            # Limpiar archivo temporal
            try:
                os.remove(current_face_path)
            except:
                pass
            return jsonify({
                "success": False, 
                "error": "❌ No hay usuarios registrados con Face ID. Regístrate primero."
            })

        # Procesar imagen actual para comparación
        current_template = procesar_imagen_para_comparacion(current_face_path)
        
        # Limpiar archivo temporal inmediatamente después de procesar
        try:
            os.remove(current_face_path)
        except Exception as e:
            print(f"⚠️ No se pudo eliminar archivo temporal: {e}")

        if current_template is None:
            return jsonify({
                "success": False, 
                "error": "❌ No se pudo procesar la imagen del rostro. Intenta nuevamente."
            })

        # Comparar con cada usuario registrado
        best_match = None
        best_similarity = 0.0
        match_details = []
        
        for usuario in usuarios:
            stored_template = load_face_template(usuario["correo"])
            
            if stored_template is not None:
                similarity, matched = compare_face_templates(stored_template, current_template)
                
                match_details.append({
                    "usuario": usuario["nombre"],
                    "correo": usuario["correo"],
                    "similitud": f"{similarity:.4f}",
                    "coincide": matched
                })
                
                print(f"🔍 Comparando con {usuario['nombre']}: {similarity:.4f} - {'✅' if matched else '❌'}")
                
                if matched and similarity > best_similarity:
                    best_similarity = similarity
                    best_match = usuario

        print(f"📊 Resumen de comparaciones: {len(match_details)} usuarios comparados")
        print(f"🏆 Mejor coincidencia: {best_match['nombre'] if best_match else 'Ninguna'} - Similitud: {best_similarity:.4f}")

        if best_match:
            # Iniciar sesión exitosa
            session["usuario_id"] = best_match["id"]
            session["usuario_nombre"] = best_match["nombre"]
            session["usuario_correo"] = best_match["correo"]
            
            clave_aes = generar_clave_aes()
            session["clave_aes_cifrada"] = cifrar_clave_aes_rsa(clave_aes)
            
            return jsonify({
                "success": True, 
                "message": f"✅ ¡Bienvenido/a {best_match['nombre']}! Face ID verificado correctamente",
                "similarity": f"{best_similarity:.4f}",
                "usuario": best_match["nombre"],
                "redirect": url_for("dashboard")
            })
        else:
            return jsonify({
                "success": False, 
                "error": "❌ Rostro no reconocido. Regístrate primero o usa correo/contraseña.",
                "similarity": f"{best_similarity:.4f}",
                "detalles": match_details
            })

    except Exception as e:
        print(f"❌ Error en verificación facial: {e}")
        import traceback
        traceback.print_exc()
        
        # Limpiar archivo temporal en caso de error
        try:
            if 'current_face_path' in locals() and current_face_path and os.path.exists(current_face_path):
                os.remove(current_face_path)
        except:
            pass
            
        return jsonify({
            "success": False, 
            "error": f"❌ Error del servidor: {str(e)}"
        })

@app.route("/login_faceid", methods=["POST"])
def login_faceid():
    """Endpoint alternativo para login con Face ID"""
    return verificar_rostro()

# ==========================================
# 🔐 RUTAS DE RECUPERACIÓN
# ==========================================
@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        correo = request.form.get("correo", "").strip()
        recaptcha_response = request.form.get("g-recaptcha-response", "")

        if not verificar_recaptcha(recaptcha_response):
            flash("⚠️ Verifica el reCAPTCHA", "error")
            return redirect(url_for("forgot_password"))

        conn = conectar_db()
        cur = conn.cursor()
        cur.execute("SELECT id FROM usuarios WHERE correo = ?", (correo,))
        usuario = cur.fetchone()

        if usuario:
            token = generar_token_recuperacion()
            cur.execute("DELETE FROM recuperacion_contraseña WHERE correo = ?", (correo,))
            cur.execute("INSERT INTO recuperacion_contraseña (correo, token) VALUES (?, ?)", 
                       (correo, token))
            conn.commit()
            
            if enviar_correo_recuperacion(correo, token):
                flash("✅ Se ha enviado un enlace de recuperación a tu correo", "success")
            else:
                flash("❌ Error al enviar el correo. Intenta más tarde", "error")
        else:
            flash("✅ Si el correo existe, se ha enviado un enlace de recuperación", "success")

        conn.close()
        return redirect(url_for("login"))

    return render_template("forgot_password.html", 
                         site_key=getattr(config, "RECAPTCHA_SITE_KEY", ""))

@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    conn = conectar_db()
    cur = conn.cursor()

    cur.execute("""
        SELECT correo FROM recuperacion_contraseña 
        WHERE token = ? AND usado = FALSE 
        AND datetime(fecha_creacion) > datetime('now', '-1 hour')
    """, (token,))

    resultado = cur.fetchone()

    if not resultado:
        conn.close()
        flash("❌ Enlace inválido o expirado", "error")
        return redirect(url_for("forgot_password"))

    correo = resultado["correo"]

    if request.method == "POST":
        password = request.form.get("password", "").strip()
        confirm_password = request.form.get("confirm_password", "").strip()
        recaptcha_response = request.form.get("g-recaptcha-response", "")

        if not verificar_recaptcha(recaptcha_response):
            flash("⚠️ Verifica el reCAPTCHA", "error")
            return render_template("reset_password.html", token=token, 
                                 site_key=getattr(config, "RECAPTCHA_SITE_KEY", ""))

        if password != confirm_password:
            flash("❌ Las contraseñas no coinciden", "error")
            return render_template("reset_password.html", token=token,
                                 site_key=getattr(config, "RECAPTCHA_SITE_KEY", ""))

        if len(password) < 6:
            flash("❌ La contraseña debe tener al menos 6 caracteres", "error")
            return render_template("reset_password.html", token=token,
                                 site_key=getattr(config, "RECAPTCHA_SITE_KEY", ""))

        hashed_password = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
        cur.execute("UPDATE usuarios SET password = ? WHERE correo = ?", 
                   (hashed_password, correo))
        cur.execute("UPDATE recuperacion_contraseña SET usado = TRUE WHERE token = ?", 
                   (token,))
        conn.commit()
        conn.close()

        flash("✅ Contraseña actualizada correctamente", "success")
        return redirect(url_for("login"))

    conn.close()
    return render_template("reset_password.html", token=token,
                         site_key=getattr(config, "RECAPTCHA_SITE_KEY", ""))

@app.route("/logout")
def logout():
    session.clear()
    flash("👋 Sesión cerrada correctamente", "success")
    return redirect(url_for("login"))

# ==========================================
# 📊 DASHBOARD
# ==========================================
@app.route("/dashboard")
def dashboard():
    if "usuario_correo" not in session:
        flash("⚠️ Debes iniciar sesión primero", "error")
        return redirect(url_for("login"))

    conn = conectar_db()
    cur = conn.cursor()
    
    cur.execute("SELECT nombre, correo FROM usuarios WHERE correo = ?", 
               (session["usuario_correo"],))
    usuario = cur.fetchone()
    
    cur.execute("SELECT nombre, descripcion, dosis, frecuencia FROM medicamentos")
    medicamentos = cur.fetchall()
    
    conn.close()

    try:
        clave_aes = descifrar_clave_aes_rsa(session["clave_aes_cifrada"])
        texto = "Datos seguros de la sesión"
        cifrado = cifrar_aes(clave_aes, texto)
        descifrado = descifrar_aes(clave_aes, cifrado)
    except Exception as e:
        print(f"⚠️ Error en cifrado: {e}")
        cifrado = b"Error"
        descifrado = "Error"

    return render_template("dashboard.html",
                         usuario=usuario,
                         medicamentos=medicamentos,
                         datos_cifrados=cifrado.hex()[:60] + "..." if isinstance(cifrado, bytes) else str(cifrado)[:60] + "...",
                         datos_descifrados=descifrado)

# ==========================================
# 📤 UPLOAD (simplificado)
# ==========================================
@app.route("/upload", methods=["GET", "POST"])
def upload():
    if "usuario_correo" not in session:
        flash("⚠️ Debes iniciar sesión primero", "error")
        return redirect(url_for("login"))

    if request.method == "POST":
        file = request.files.get("file")
        if file and allowed_file(file.filename):
            filename = file.filename
            file_path = os.path.join(config.UPLOAD_FOLDER, filename)
            file.save(file_path)
            flash("✅ Archivo subido correctamente", "success")
        else:
            flash("❌ Tipo de archivo no permitido", "error")

    return render_template("upload.html")

# ==========================================
# 🚀 INICIALIZACIÓN
# ==========================================
def get_local_ip():
    """Obtiene la IP local para acceso en red"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

if __name__ == "__main__":
    # Inicializar base de datos
    inicializar_bd()
    
    # Configuración del servidor
    local_ip = get_local_ip()
    host = "0.0.0.0"  # IMPORTANTE: Esto permite acceso desde cualquier IP en la red
    port = 5000
    
    print("=" * 60)
    print("🚀 Glucocontrol Seguro - Sistema Biométrico")
    print("=" * 60)
    print(f"📍 IP Local: {local_ip}")
    print(f"📱 Acceso local: http://localhost:{port}")
    print(f"🌐 Acceso en red: http://{local_ip}:{port}")
    print(f"📧 Otros dispositivos: http://[TU-IP]:{port}")
    print("=" * 60)
    print("💡 Para acceder desde otros dispositivos:")
    print(f"   • Usa: http://{local_ip}:{port}")
    print("   • Asegúrate de estar en la misma red WiFi")
    print("=" * 60)
    
    # Configuración SSL (opcional)
    ssl_cert = getattr(config, "SSL_CERT", None)
    ssl_key = getattr(config, "SSL_KEY", None)
    ssl_context = None
    
    if ssl_cert and ssl_key and os.path.exists(ssl_cert) and os.path.exists(ssl_key):
        ssl_context = (ssl_cert, ssl_key)
        print("🔒 SSL habilitado")
    else:
        print("⚠️  SSL no configurado - Usando HTTP")
    
    # Iniciar servidor
    app.run(host=host, port=port, ssl_context=ssl_context, debug=True)