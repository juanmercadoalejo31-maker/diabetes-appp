# models.py
import sqlite3
import os
from datetime import datetime, timedelta
import secrets
from config import DATABASE_PATH, TOKEN_EXPIRATION_HOURS

def conectar_db():
    return sqlite3.connect(DATABASE_PATH)

def crear_tabla_tokens():
    """Crear tabla para tokens de recuperación si no existe"""
    conexion = conectar_db()
    cursor = conexion.cursor()
    
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS tokens_recuperacion (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        correo TEXT NOT NULL,
        token TEXT UNIQUE NOT NULL,
        fecha_creacion DATETIME DEFAULT CURRENT_TIMESTAMP,
        utilizado INTEGER DEFAULT 0
    )
    """)
    
    conexion.commit()
    conexion.close()
    print("✅ Tabla 'tokens_recuperacion' creada/verificada.")

def generar_token_recuperacion(correo):
    """Generar un token único para recuperación de contraseña"""
    conexion = conectar_db()
    cursor = conexion.cursor()
    
    # Invalidar tokens anteriores del mismo usuario
    cursor.execute("UPDATE tokens_recuperacion SET utilizado = 1 WHERE correo = ?", (correo,))
    
    # Generar nuevo token
    token = secrets.token_urlsafe(32)
    
    # Insertar nuevo token
    cursor.execute(
        "INSERT INTO tokens_recuperacion (correo, token) VALUES (?, ?)",
        (correo, token)
    )
    
    conexion.commit()
    conexion.close()
    
    print(f"✅ Token generado para: {correo}")
    return token

def validar_token(token):
    """Validar si un token es válido y no ha expirado"""
    conexion = conectar_db()
    cursor = conexion.cursor()
    
    cursor.execute("""
    SELECT correo, fecha_creacion, utilizado 
    FROM tokens_recuperacion 
    WHERE token = ? AND utilizado = 0
    """, (token,))
    
    resultado = cursor.fetchone()
    conexion.close()
    
    if not resultado:
        print(f"❌ Token no encontrado o ya utilizado: {token}")
        return None
    
    correo, fecha_creacion, utilizado = resultado
    
    # Verificar expiración (1 hora)
    fecha_creacion = datetime.strptime(fecha_creacion, '%Y-%m-%d %H:%M:%S')
    tiempo_expiracion = timedelta(hours=TOKEN_EXPIRATION_HOURS)
    
    if datetime.now() - fecha_creacion > tiempo_expiracion:
        print(f"❌ Token expirado: {token}")
        return None
    
    print(f"✅ Token válido para: {correo}")
    return correo

def marcar_token_como_utilizado(token):
    """Marcar un token como utilizado"""
    conexion = conectar_db()
    cursor = conexion.cursor()
    
    cursor.execute(
        "UPDATE tokens_recuperacion SET utilizado = 1 WHERE token = ?",
        (token,)
    )
    
    conexion.commit()
    conexion.close()
    print(f"✅ Token marcado como utilizado: {token}")

# Crear la tabla al importar el módulo
crear_tabla_tokens()