import os

# ==========================================
# 📦 CONFIGURACIÓN GENERAL DEL PROYECTO
# ==========================================
BASE_DIR = os.path.abspath(os.path.dirname(__file__))

# 🔑 Clave secreta de Flask
SECRET_KEY = "tu_clave_super_secreta_12345"

# 💾 Base de datos
DATABASE_PATH = os.path.join(BASE_DIR, "database", "usuarios.db")
ALLOWED_EXTENSIONS = {"pdf", "png", "jpg", "jpeg", "txt"}

# 🔐 Claves RSA
KEYS_DIR = os.path.join(BASE_DIR, "keys")
PRIVATE_KEY_PATH = os.path.join(KEYS_DIR, "private.pem")
PUBLIC_KEY_PATH = os.path.join(KEYS_DIR, "public.pem")

# 🧾 Certificados SSL
CERTS_DIR = os.path.join(BASE_DIR, "certs")
SSL_CERT = os.path.join(CERTS_DIR, "cert.pem")
SSL_KEY = os.path.join(CERTS_DIR, "key.pem")

# 📁 Carpeta para subir archivos
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")

# 🔁 reCAPTCHA
RECAPTCHA_SITE_KEY = "6LdhdhIsAAAAANOvIkh4gQ2yzQzmWlyuEGbaAhc8"
RECAPTCHA_SECRET_KEY = "6LdhdhIsAAAAAPneaBoeYED2FRpxN9FtqVdiomUR"

# ⏰ Configuración de tokens de recuperación
TOKEN_EXPIRATION_MINUTES = 30  # El token expira en 30 minutos
MAX_TOKEN_ATTEMPTS = 3  # Máximo de intentos por token

# ⚙️ Config Flask adicional
DEBUG = True
HOST = "localhost"
PORT = 5000

# ==========================================
# 📧 CONFIGURACIÓN DE CORREO ELECTRÓNICO
# ==========================================
EMAIL_HOST = 'smtp.gmail.com'  # Servidor SMTP de Gmail
EMAIL_PORT = 587
EMAIL_USE_TLS = True
EMAIL_USER = 'tu_correo@gmail.com'  # Cambiar por tu correo real
EMAIL_PASSWORD = 'tu_contraseña_de_aplicacion'  # Contraseña de aplicación de Gmail
EMAIL_FROM = 'tu_correo@gmail.com'  # Mismo que EMAIL_USER

# ==========================================
# 📂 CREACIÓN DE CARPETAS NECESARIAS
# ==========================================
# Crear carpetas si no existen
os.makedirs(os.path.join(BASE_DIR, "database"), exist_ok=True)
os.makedirs(KEYS_DIR, exist_ok=True)
os.makedirs(CERTS_DIR, exist_ok=True)
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(os.path.join(BASE_DIR, "biometric_data"), exist_ok=True)  # Para datos biométricos

# ==========================================
# 🔧 Función para inicializar Flask con config
# ==========================================
def init_app_config(app):
    app.secret_key = SECRET_KEY
    app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
    app.config["DATABASE_PATH"] = DATABASE_PATH
    app.config["SSL_CERT"] = SSL_CERT
    app.config["SSL_KEY"] = SSL_KEY
    app.config["ALLOWED_EXTENSIONS"] = ALLOWED_EXTENSIONS
    # Configuración adicional para sesiones
    app.config["SESSION_COOKIE_SECURE"] = True  # Solo enviar cookies sobre HTTPS
    app.config["SESSION_COOKIE_HTTPONLY"] = True  # Prevenir acceso JavaScript a cookies
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"  # Protección CSRF