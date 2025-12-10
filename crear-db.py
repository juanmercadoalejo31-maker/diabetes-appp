import sqlite3
import os
import bcrypt
from datetime import datetime
import json

# ==========================================
# 📌 RUTA DE LA BASE DE DATOS
# ==========================================
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_DIR = os.path.join(BASE_DIR, "database")
DB_PATH = os.path.join(DB_DIR, "sistema_diabetes.db")

os.makedirs(DB_DIR, exist_ok=True)

# ==========================================
# 📌 CONEXIÓN
# ==========================================
conexion = sqlite3.connect(DB_PATH)
cursor = conexion.cursor()

# ==========================================
# 🧑‍⚕️ TABLA DE USUARIOS (personal médico)
# ==========================================
cursor.execute("""
CREATE TABLE IF NOT EXISTS usuarios (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    correo TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    nombre TEXT NOT NULL,
    rol TEXT DEFAULT 'medico',        -- medico, admin, enfermero
    telefono TEXT,
    especialidad TEXT,
    activo BOOLEAN DEFAULT 1,
    fecha_registro TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    ultimo_login TIMESTAMP,
    intentos_login INTEGER DEFAULT 0,
    bloqueado BOOLEAN DEFAULT 0
);
""")

# ==========================================
# 👨‍⚕️ TABLA DE PACIENTES CON DIABETES
# ==========================================
cursor.execute("""
CREATE TABLE IF NOT EXISTS pacientes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nombre TEXT NOT NULL,
    edad INTEGER,
    sexo TEXT,                        -- M, F, Otro
    tipo_diabetes TEXT,               -- Tipo 1, Tipo 2, Gestacional
    telefono TEXT,
    email TEXT,
    direccion TEXT,
    fecha_nacimiento TEXT,
    fecha_diagnostico TEXT,
    medico_asignado INTEGER,
    historial_medico TEXT,
    alergias TEXT,
    contacto_emergencia TEXT,
    telefono_emergencia TEXT,
    activo BOOLEAN DEFAULT 1,
    fecha_registro TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (medico_asignado) REFERENCES usuarios(id)
);
""")

# ==========================================
# 💊 TABLA DE MEDICAMENTOS PARA DIABETES
# ==========================================
cursor.execute("""
CREATE TABLE IF NOT EXISTS medicamentos (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nombre TEXT NOT NULL,
    tipo TEXT,                        -- insulina, pastillas, GLP-1, etc.
    dosis TEXT,
    descripcion TEXT,
    contraindicaciones TEXT,
    laboratorio TEXT,
    activo BOOLEAN DEFAULT 1,
    fecha_registro TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
""")

# ==========================================
# 📋 ASIGNACIÓN DE MEDICAMENTOS A PACIENTES
# ==========================================
cursor.execute("""
CREATE TABLE IF NOT EXISTS tratamientos (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    paciente_id INTEGER,
    medicamento_id INTEGER,
    dosis_prescrita TEXT,
    frecuencia TEXT,                  -- 1 diaria, 2 diarias, semanal...
    via_administracion TEXT,          -- oral, subcutánea, etc.
    hora_administracion TEXT,         -- 08:00, 20:00, etc.
    fecha_inicio TEXT,
    fecha_fin TEXT,
    indicaciones TEXT,
    estado TEXT DEFAULT 'activo',     -- activo, suspendido, completado
    fecha_registro TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (paciente_id) REFERENCES pacientes(id),
    FOREIGN KEY (medicamento_id) REFERENCES medicamentos(id)
);
""")

# ==========================================
# 📊 REGISTROS GLUCÉMICOS
# ==========================================
cursor.execute("""
CREATE TABLE IF NOT EXISTS registros_glucemia (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    paciente_id INTEGER,
    nivel_glucosa REAL,               -- mg/dL
    tipo_medicion TEXT,               -- ayunas, postprandial, aleatoria
    fecha_medicion TIMESTAMP,
    hora_medicion TEXT,
    notas TEXT,
    estado TEXT,                      -- normal, alto, bajo, crítico
    dispositivo TEXT,                 -- glucómetro, sensor
    fecha_registro TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (paciente_id) REFERENCES pacientes(id)
);
""")

# ==========================================
# 🩺 CONSULTAS MÉDICAS
# ==========================================
cursor.execute("""
CREATE TABLE IF NOT EXISTS consultas (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    paciente_id INTEGER,
    medico_id INTEGER,
    fecha_consulta TEXT,
    hora_consulta TEXT,
    motivo TEXT,
    diagnostico TEXT,
    tratamiento TEXT,
    observaciones TEXT,
    peso REAL,
    altura REAL,
    presion_arterial TEXT,
    imc REAL,
    proxima_cita TEXT,
    estado TEXT DEFAULT 'realizada',  -- programada, realizada, cancelada
    fecha_registro TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (paciente_id) REFERENCES pacientes(id),
    FOREIGN KEY (medico_id) REFERENCES usuarios(id)
);
""")

# ==========================================
# 🔐 TABLAS DE BIOMETRÍAS
# ==========================================

# Huella dactilar
cursor.execute("""
CREATE TABLE IF NOT EXISTS biometricos_huella (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    usuario_id INTEGER,
    public_key TEXT,
    credential_id TEXT UNIQUE,
    dispositivo TEXT,
    activo BOOLEAN DEFAULT 1,
    fecha_registro TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (usuario_id) REFERENCES usuarios(id)
);
""")

# Rostro
cursor.execute("""
CREATE TABLE IF NOT EXISTS biometricos_facial (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    usuario_id INTEGER,
    datos_facial TEXT,                -- Datos faciales codificados
    descriptor_facial TEXT,           -- Descriptor facial para comparación
    imagen_rostro BLOB,               -- Imagen del rostro
    confianza_minima REAL DEFAULT 0.8,
    activo BOOLEAN DEFAULT 1,
    fecha_registro TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (usuario_id) REFERENCES usuarios(id)
);
""")

# Voz
cursor.execute("""
CREATE TABLE IF NOT EXISTS biometricos_voz (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    usuario_id INTEGER,
    huella_voz TEXT,                  -- Huella vocal codificada
    frase TEXT,                       -- Frase de entrenamiento
    audio_muestra BLOB,               -- Audio de muestra
    confianza_minima REAL DEFAULT 0.7,
    activo BOOLEAN DEFAULT 1,
    fecha_registro TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (usuario_id) REFERENCES usuarios(id)
);
""")

# ==========================================
# 🕓 HISTORIAL DE ACCESOS (LOGIN BIOMÉTRICO)
# ==========================================
cursor.execute("""
CREATE TABLE IF NOT EXISTS historial_accesos (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    usuario_id INTEGER,
    metodo TEXT,                      -- rostro, huella, voz, contraseña
    dispositivo TEXT,
    ip_address TEXT,
    user_agent TEXT,
    exito BOOLEAN,
    confianza REAL,                   -- Nivel de confianza biométrica
    mensaje_error TEXT,
    fecha TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (usuario_id) REFERENCES usuarios(id)
);
""")

# ==========================================
# 🚨 ALERTAS DE MEDICAMENTOS
# ==========================================
cursor.execute("""
CREATE TABLE IF NOT EXISTS alertas (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    paciente_id INTEGER,
    tratamiento_id INTEGER,
    tipo TEXT,                        -- medicamento, glucosa, cita
    mensaje TEXT,
    prioridad TEXT DEFAULT 'media',   -- baja, media, alta, critica
    estado TEXT DEFAULT 'pendiente',  -- pendiente, atendida, cancelada
    fecha_alerta TIMESTAMP,
    fecha_atencion TIMESTAMP,
    leido BOOLEAN DEFAULT 0,
    fecha_registro TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (paciente_id) REFERENCES pacientes(id),
    FOREIGN KEY (tratamiento_id) REFERENCES tratamientos(id)
);
""")

# ==========================================
# 📅 RECORDATORIOS DE MEDICAMENTOS
# ==========================================
cursor.execute("""
CREATE TABLE IF NOT EXISTS recordatorios (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    paciente_id INTEGER,
    tratamiento_id INTEGER,
    titulo TEXT,
    mensaje TEXT,
    fecha_recordatorio TEXT,
    hora_recordatorio TEXT,
    repetir TEXT,                     -- una_vez, diario, semanal
    estado TEXT DEFAULT 'pendiente',  -- pendiente, completado, cancelado
    confirmado BOOLEAN DEFAULT 0,
    fecha_confirmacion TIMESTAMP,
    fecha_registro TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (paciente_id) REFERENCES pacientes(id),
    FOREIGN KEY (tratamiento_id) REFERENCES tratamientos(id)
);
""")

# ==========================================
# 📈 METAS GLUCÉMICAS
# ==========================================
cursor.execute("""
CREATE TABLE IF NOT EXISTS metas_glucemia (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    paciente_id INTEGER,
    tipo_medicion TEXT,               -- ayunas, postprandial, aleatoria
    meta_minima REAL,
    meta_maxima REAL,
    activo BOOLEAN DEFAULT 1,
    fecha_registro TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (paciente_id) REFERENCES pacientes(id)
);
""")

# ==========================================
# 🔐 CONFIGURACIÓN DE SEGURIDAD
# ==========================================
cursor.execute("""
CREATE TABLE IF NOT EXISTS configuracion_seguridad (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    clave TEXT UNIQUE,
    valor TEXT,
    descripcion TEXT,
    fecha_actualizacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
""")

# ==========================================
# 👤 INSERTAR USUARIOS DE PRUEBA
# ==========================================
usuarios_prueba = [
    {
        "correo": "medico1@tesjo.edu.mx",
        "password": "password123",
        "nombre": "Dr. Juan Pérez",
        "rol": "medico",
        "telefono": "555-123-4567",
        "especialidad": "Endocrinología"
    },
    {
        "correo": "medico2@tesjo.edu.mx",
        "password": "password123",
        "nombre": "Dra. María García",
        "rol": "medico",
        "telefono": "555-987-6543",
        "especialidad": "Medicina Interna"
    },
    {
        "correo": "admin@tesjo.edu.mx",
        "password": "admin123",
        "nombre": "Administrador Sistema",
        "rol": "admin",
        "telefono": "555-555-5555",
        "especialidad": "Administración"
    },
    {
        "correo": "enfermero1@tesjo.edu.mx",
        "password": "password123",
        "nombre": "Enf. Roberto López",
        "rol": "enfermero",
        "telefono": "555-111-2233",
        "especialidad": "Enfermería"
    }
]

for u in usuarios_prueba:
    cursor.execute("SELECT * FROM usuarios WHERE correo = ?", (u["correo"],))
    if not cursor.fetchone():
        hash_pw = bcrypt.hashpw(u["password"].encode("utf-8"), bcrypt.gensalt())
        cursor.execute(
            """INSERT INTO usuarios (correo, password, nombre, rol, telefono, especialidad) 
               VALUES (?, ?, ?, ?, ?, ?)""",
            (u["correo"], hash_pw, u["nombre"], u["rol"], u["telefono"], u["especialidad"])
        )
        print(f"✅ Usuario creado: {u['correo']} / {u['password']}")
    else:
        print(f"⚠️ El usuario {u['correo']} ya existe.")

# ==========================================
# 👨‍⚕️ INSERTAR PACIENTES DE PRUEBA
# ==========================================
pacientes_prueba = [
    {
        "nombre": "Carlos Rodríguez",
        "edad": 45,
        "sexo": "M",
        "tipo_diabetes": "Tipo 2",
        "telefono": "555-444-3322",
        "email": "carlos.rodriguez@email.com",
        "direccion": "Av. Principal 123",
        "fecha_nacimiento": "1978-05-15",
        "fecha_diagnostico": "2015-03-10",
        "medico_asignado": 1,
        "historial_medico": "Hipertensión controlada",
        "alergias": "Penicilina"
    },
    {
        "nombre": "Ana Martínez",
        "edad": 32,
        "sexo": "F",
        "tipo_diabetes": "Tipo 1",
        "telefono": "555-777-8899",
        "email": "ana.martinez@email.com",
        "direccion": "Calle Secundaria 456",
        "fecha_nacimiento": "1991-08-22",
        "fecha_diagnostico": "2010-11-05",
        "medico_asignado": 2,
        "historial_medico": "Diagnosticada a los 21 años",
        "alergias": "Ninguna"
    },
    {
        "nombre": "Miguel Sánchez",
        "edad": 58,
        "sexo": "M",
        "tipo_diabetes": "Tipo 2",
        "telefono": "555-222-3344",
        "email": "miguel.sanchez@email.com",
        "direccion": "Plaza Central 789",
        "fecha_nacimiento": "1965-12-03",
        "fecha_diagnostico": "2018-07-20",
        "medico_asignado": 1,
        "historial_medico": "Obesidad, apnea del sueño",
        "alergias": "Sulfas"
    }
]

for p in pacientes_prueba:
    cursor.execute("SELECT * FROM pacientes WHERE email = ?", (p["email"],))
    if not cursor.fetchone():
        cursor.execute(
            """INSERT INTO pacientes (nombre, edad, sexo, tipo_diabetes, telefono, email, 
               direccion, fecha_nacimiento, fecha_diagnostico, medico_asignado, 
               historial_medico, alergias, contacto_emergencia, telefono_emergencia) 
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (p["nombre"], p["edad"], p["sexo"], p["tipo_diabetes"], p["telefono"], 
             p["email"], p["direccion"], p["fecha_nacimiento"], p["fecha_diagnostico"],
             p["medico_asignado"], p["historial_medico"], p["alergias"],
             "Esposa", "555-999-8888")
        )
        print(f"✅ Paciente creado: {p['nombre']}")
    else:
        print(f"⚠️ El paciente {p['email']} ya existe.")

# ==========================================
# 💊 INSERTAR MEDICAMENTOS COMUNES PARA DIABETES
# ==========================================
medicamentos_prueba = [
    {
        "nombre": "Metformina",
        "tipo": "pastillas",
        "dosis": "500mg",
        "descripcion": "Medicamento oral para diabetes tipo 2",
        "contraindicaciones": "Insuficiencia renal, acidosis láctica",
        "laboratorio": "Genérico"
    },
    {
        "nombre": "Insulina Glargina",
        "tipo": "insulina",
        "dosis": "100 UI/mL",
        "descripcion": "Insulina de acción prolongada",
        "contraindicaciones": "Hipoglucemia, alergia a insulina",
        "laboratorio": "Sanofi"
    },
    {
        "nombre": "Glibenclamida",
        "tipo": "pastillas",
        "dosis": "5mg",
        "descripcion": "Estimula la producción de insulina",
        "contraindicaciones": "Diabetes tipo 1, embarazo",
        "laboratorio": "Genérico"
    },
    {
        "nombre": "Liraglutida",
        "tipo": "GLP-1",
        "dosis": "1.2mg",
        "descripcion": "Análogo de GLP-1 para diabetes tipo 2",
        "contraindicaciones": "Antecedentes de cáncer medular tiroideo",
        "laboratorio": "Novo Nordisk"
    }
]

for m in medicamentos_prueba:
    cursor.execute("SELECT * FROM medicamentos WHERE nombre = ?", (m["nombre"],))
    if not cursor.fetchone():
        cursor.execute(
            """INSERT INTO medicamentos (nombre, tipo, dosis, descripcion, contraindicaciones, laboratorio) 
               VALUES (?, ?, ?, ?, ?, ?)""",
            (m["nombre"], m["tipo"], m["dosis"], m["descripcion"], m["contraindicaciones"], m["laboratorio"])
        )
        print(f"✅ Medicamento creado: {m['nombre']}")
    else:
        print(f"⚠️ El medicamento {m['nombre']} ya existe.")

# ==========================================
# 📋 INSERTAR TRATAMIENTOS DE PRUEBA
# ==========================================
tratamientos_prueba = [
    {
        "paciente_id": 1,
        "medicamento_id": 1,
        "dosis_prescrita": "500mg",
        "frecuencia": "2 veces al día",
        "via_administracion": "oral",
        "hora_administracion": "08:00,20:00",
        "fecha_inicio": "2024-01-15",
        "fecha_fin": "2024-07-15",
        "indicaciones": "Tomar con alimentos"
    },
    {
        "paciente_id": 2,
        "medicamento_id": 2,
        "dosis_prescrita": "20 UI",
        "frecuencia": "1 vez al día",
        "via_administracion": "subcutánea",
        "hora_administracion": "22:00",
        "fecha_inicio": "2024-01-10",
        "fecha_fin": None,
        "indicaciones": "Aplicar en abdomen o muslo"
    }
]

for t in tratamientos_prueba:
    cursor.execute(
        "SELECT * FROM tratamientos WHERE paciente_id = ? AND medicamento_id = ?", 
        (t["paciente_id"], t["medicamento_id"])
    )
    if not cursor.fetchone():
        cursor.execute(
            """INSERT INTO tratamientos (paciente_id, medicamento_id, dosis_prescrita, frecuencia, 
               via_administracion, hora_administracion, fecha_inicio, fecha_fin, indicaciones) 
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (t["paciente_id"], t["medicamento_id"], t["dosis_prescrita"], t["frecuencia"],
             t["via_administracion"], t["hora_administracion"], t["fecha_inicio"], 
             t["fecha_fin"], t["indicaciones"])
        )
        print(f"✅ Tratamiento creado para paciente ID: {t['paciente_id']}")
    else:
        print(f"⚠️ El tratamiento ya existe para paciente ID: {t['paciente_id']}")

# ==========================================
# 📊 INSERTAR REGISTROS GLUCÉMICOS DE PRUEBA
# ==========================================
registros_prueba = [
    {
        "paciente_id": 1,
        "nivel_glucosa": 125.0,
        "tipo_medicion": "ayunas",
        "fecha_medicion": "2024-01-20 08:00:00",
        "hora_medicion": "08:00",
        "notas": "Nivel dentro de rango objetivo",
        "estado": "normal",
        "dispositivo": "glucómetro"
    },
    {
        "paciente_id": 2,
        "nivel_glucosa": 180.0,
        "tipo_medicion": "postprandial",
        "fecha_medicion": "2024-01-20 14:30:00",
        "hora_medicion": "14:30",
        "notas": "Nivel elevado después del almuerzo",
        "estado": "alto",
        "dispositivo": "sensor"
    }
]

for r in registros_prueba:
    cursor.execute(
        "INSERT INTO registros_glucemia (paciente_id, nivel_glucosa, tipo_medicion, fecha_medicion, hora_medicion, notas, estado, dispositivo) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (r["paciente_id"], r["nivel_glucosa"], r["tipo_medicion"], r["fecha_medicion"], r["hora_medicion"], r["notas"], r["estado"], r["dispositivo"])
    )

# ==========================================
# 🔐 INSERTAR CONFIGURACIÓN DE SEGURIDAD
# ==========================================
config_seguridad = [
    ("intentos_maximos_login", "5", "Número máximo de intentos de login fallidos"),
    ("bloqueo_temporal_minutos", "30", "Tiempo de bloqueo tras intentos fallidos"),
    ("confianza_minima_rostro", "0.8", "Confianza mínima para reconocimiento facial"),
    ("confianza_minima_voz", "0.7", "Confianza mínima para reconocimiento de voz"),
    ("session_timeout_minutes", "60", "Tiempo de expiración de sesión en minutos"),
    ("requerir_2fa", "0", "Requerir autenticación de dos factores")
]

for config in config_seguridad:
    cursor.execute(
        "INSERT OR REPLACE INTO configuracion_seguridad (clave, valor, descripcion) VALUES (?, ?, ?)",
        config
    )

# ==========================================
# ✔ GUARDAR Y CERRAR
# ==========================================
conexion.commit()
conexion.close()

print("\n" + "="*50)
print("✅ BASE DE DATOS CREADA CORRECTAMENTE")
print("="*50)
print("👤 USUARIOS DE PRUEBA (contraseña 'password123'):")
print(" - medico1@tesjo.edu.mx (Endocrinología)")
print(" - medico2@tesjo.edu.mx (Medicina Interna)") 
print(" - admin@tesjo.edu.mx (Administrador)")
print(" - enfermero1@tesjo.edu.mx (Enfermería)")
print("\n👨‍⚕️ PACIENTES DE PRUEBA CREADOS:")
print(" - Carlos Rodríguez (Diabetes Tipo 2)")
print(" - Ana Martínez (Diabetes Tipo 1)")
print(" - Miguel Sánchez (Diabetes Tipo 2)")
print("\n💊 MEDICAMENTOS REGISTRADOS:")
print(" - Metformina, Insulina Glargina, Glibenclamida, Liraglutida")
print("="*50)