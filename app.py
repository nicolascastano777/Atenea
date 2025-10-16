from flask import Flask, request, render_template, redirect, url_for, session, flash
from flask_bcrypt import Bcrypt
import sqlite3
import os
import requests
import urllib.parse

app = Flask(__name__)
bcrypt = Bcrypt(app)

# Permitir OAuth en HTTP (Solo en desarrollo)
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

# Clave secreta para sesiones
app.secret_key = "advpjsh"

# Configuración de Base de Datos SQLite
def init_db():
    conn = sqlite3.connect('usuarios.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS usuarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            usuario TEXT UNIQUE,
            email TEXT UNIQUE NOT NULL,
            contrasena TEXT,
            google_id TEXT
        )
    ''')
    conn.commit()
    conn.close()

def get_db_connection():
    conn = sqlite3.connect('usuarios.db')
    conn.row_factory = sqlite3.Row
    return conn

# Inicializar la base de datos al arrancar
init_db()

# Configuración de Google OAuth
GOOGLE_CLIENT_ID = '275736512925-shv6n8co3ev88suae6b0ihoo2ijqjbq3.apps.googleusercontent.com'
GOOGLE_CLIENT_SECRET = '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'
GOOGLE_REDIRECT_URI = 'http://127.0.0.1:5000/google_login/google/authorized'



@app.route('/google_login/google')
def google_login():
    auth_url = 'https://accounts.google.com/o/oauth2/v2/auth'
    params = {
        'client_id': GOOGLE_CLIENT_ID,
        'redirect_uri': GOOGLE_REDIRECT_URI,
        'scope': 'https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/userinfo.profile openid',
        'response_type': 'code',
        'access_type': 'offline',
        'prompt': 'consent',
        'include_granted_scopes': 'true'
    }
    
    auth_url_with_params = auth_url + '?' + urllib.parse.urlencode(params)
    return redirect(auth_url_with_params)

@app.route('/google_login/google/authorized')
def google_authorized():
    code = request.args.get('code')
    error = request.args.get('error')
    
    if error:
        flash(f"Error de autorización con Google: {error}", "error")
        return redirect(url_for('login'))
    
    if not code:
        flash("No se recibió código de autorización de Google.", "error")
        return redirect(url_for('login'))

    try:
        # Intercambiar el código por un token de acceso
        token_url = 'https://oauth2.googleapis.com/token'
        token_data = {
            'client_id': GOOGLE_CLIENT_ID,
            'client_secret': GOOGLE_CLIENT_SECRET,
            'code': code,
            'grant_type': 'authorization_code',
            'redirect_uri': GOOGLE_REDIRECT_URI
        }
        
        token_response = requests.post(token_url, data=token_data)
        token_json = token_response.json()
        
        if 'access_token' not in token_json:
            flash("Error al obtener token de acceso de Google.", "error")
            return redirect(url_for('login'))
        
        access_token = token_json['access_token']
        
        # Obtener información del usuario usando el token
        user_info_url = 'https://www.googleapis.com/oauth2/v3/userinfo'
        headers = {'Authorization': f'Bearer {access_token}'}
        user_response = requests.get(user_info_url, headers=headers)
        user_info = user_response.json()

        # Verificar que Google haya enviado un email
        if 'email' not in user_info:
            flash("Error: Google no proporcionó un email.", "error")
            return redirect(url_for('login'))

        # Obtener el ID único de Google
        google_id = user_info.get("sub")

        # Verificar si el usuario ya está registrado
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM usuarios WHERE email = ?', (user_info['email'],)).fetchone()
        
        if not user:
            # Registrar nuevo usuario con Google
            conn.execute('''
                INSERT INTO usuarios (usuario, email, google_id) 
                VALUES (?, ?, ?)
            ''', (user_info.get('name', 'Usuario sin nombre'), user_info['email'], google_id))
            conn.commit()
        
        conn.close()

        # Iniciar sesión guardando el nombre en la sesión
        session['usuario'] = user_info.get('name', 'Usuario sin nombre')
        session['auth_method'] = 'google'  # Marcar método de autenticación
        flash("¡Inicio de sesión exitoso con Google!", "success")
        
        return redirect(url_for('pagina_principal'))
        
    except Exception as e:
        flash("Error durante la autenticación con Google. Intenta nuevamente.", "error")
        return redirect(url_for('login'))

@app.route('/')
def home():
    if 'usuario' not in session:
        return redirect(url_for('login'))
    return redirect(url_for('pagina_principal'))

@app.route('/registro', methods=['GET', 'POST'])
def registro():
    if request.method == 'POST':
        email = request.form['email']
        contrasena = request.form['contrasena']
        
        # Generar nombre de usuario automáticamente desde el email
        usuario = email.split('@')[0]

        # Verificar si el correo ya está registrado
        conn = get_db_connection()
        existing_user = conn.execute('SELECT * FROM usuarios WHERE email = ?', (email,)).fetchone()
        
        if existing_user:
            conn.close()
            flash("El correo electrónico ya está registrado.")
            return redirect(url_for('registro'))

        # Verificar si el nombre de usuario ya existe y modificarlo si es necesario
        existing_username = conn.execute('SELECT * FROM usuarios WHERE usuario = ?', (usuario,)).fetchone()
        if existing_username:
            counter = 1
            original_usuario = usuario
            while existing_username:
                usuario = f"{original_usuario}{counter}"
                existing_username = conn.execute('SELECT * FROM usuarios WHERE usuario = ?', (usuario,)).fetchone()
                counter += 1

        # Hashear la contraseña
        hashed_password = bcrypt.generate_password_hash(contrasena).decode('utf-8')

        # Insertar usuario en la base de datos
        conn.execute('''
            INSERT INTO usuarios (usuario, email, contrasena) 
            VALUES (?, ?, ?)
        ''', (usuario, email, hashed_password))
        conn.commit()
        conn.close()
        
        session['usuario'] = usuario
        session['auth_method'] = 'local'  # Marcar método de autenticación
        flash("¡Registro exitoso! Bienvenido a Atenea.", "success")
        return redirect(url_for('pagina_principal'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # En caso de que aún se envíe un POST desde el formulario,
        # simplemente redirigir a Google OAuth
        return redirect(url_for('google_login'))

    return render_template('login.html')

@app.route('/pagina_principal')
def pagina_principal():
    if 'usuario' not in session:
        return redirect(url_for('login'))
    
    # Obtener información completa del usuario para el chat
    usuario = session['usuario']
    conn = get_db_connection()
    user_data = conn.execute('SELECT * FROM usuarios WHERE usuario = ?', (usuario,)).fetchone()
    conn.close()
    
    if user_data:
        return render_template('AteneaChat.html', usuario=user_data['usuario'], email=user_data['email'])
    else:
        return redirect(url_for('login'))

@app.route('/mi_perfil')
def mi_perfil():
    if 'usuario' not in session:
        return redirect(url_for('login'))
    
    usuario = session['usuario']
    auth_method = session.get('auth_method', 'unknown')
    
    # Mapear método de autenticación a texto legible
    auth_method_text = {
        'google': 'Google OAuth',
        'local': 'Cuenta Local',
        'unknown': 'Desconocido'
    }
    
    conn = get_db_connection()
    user_data = conn.execute('SELECT * FROM usuarios WHERE usuario = ?', (usuario,)).fetchone()
    conn.close()
    
    if user_data:
        return render_template('mi_perfil.html', 
                             usuario=user_data['usuario'], 
                             email=user_data['email'],
                             auth_method=auth_method_text.get(auth_method, 'Desconocido'))
    else:
        return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.pop('usuario', None)
    session.pop('auth_method', None)
    flash("Sesión cerrada exitosamente.", "success")
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)