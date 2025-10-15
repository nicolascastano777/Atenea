from flask import Flask, request, render_template, redirect, url_for, session, flash
from flask_bcrypt import Bcrypt
import sqlite3
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
from itsdangerous import URLSafeTimedSerializer as Serializer
import os
import pathlib
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
    """Inicializar la base de datos SQLite"""
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
    """Obtener conexión a la base de datos"""
    conn = sqlite3.connect('usuarios.db')
    conn.row_factory = sqlite3.Row
    return conn

# Inicializar la base de datos al arrancar
init_db()

# Configuración de SendGrid
SENDGRID_API_KEY = None  # Configurar con tu API key real cuando esté disponible

# Serializador para crear y verificar tokens
serializer = Serializer(app.secret_key, salt='password-reset-salt')

# Configuración de Google OAuth
GOOGLE_CLIENT_ID = '275736512925-shv6n8co3ev88suae6b0ihoo2ijqjbq3.apps.googleusercontent.com'
GOOGLE_CLIENT_SECRET = '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'
GOOGLE_REDIRECT_URI = 'http://127.0.0.1:5000/google_login/google/authorized'

@app.route('/google_login/google')
def google_login():
    """Redirige a Google para autenticación"""
    # Crear la URL de autorización de Google
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
    print(f"Redirigiendo a: {auth_url_with_params}")
    return redirect(auth_url_with_params)

@app.route('/google_login/google/authorized')
def google_authorized():
    """Callback que maneja la respuesta de Google"""
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
        
        print("Información del usuario de Google:", user_info)

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
        flash("¡Inicio de sesión exitoso con Google!", "success")
        
        return redirect(url_for('pagina_principal'))
        
    except Exception as e:
        print(f"Error en Google OAuth: {e}")
        flash("Error durante la autenticación con Google. Intenta nuevamente.", "error")
        return redirect(url_for('login'))
def enviar_email(destinatario, asunto, cuerpo):
    if SENDGRID_API_KEY is None:
        print(f"SendGrid no configurado. Email simulado enviado a: {destinatario}")
        print(f"Asunto: {asunto}")
        print(f"Contenido: {cuerpo}")
        return
        
    mensaje = Mail(
        from_email='tu correo remitente que creaste en SendGrid aquí',  # Cambia esto por tu correo
        to_emails=destinatario,
        subject=asunto,
        html_content=cuerpo
    )
    try:
        sg = SendGridAPIClient(SENDGRID_API_KEY)  # Usa tu clave API de SendGrid directamente
        response = sg.send(mensaje)
        print(f"Correo enviado con éxito! Status code: {response.status_code}")
    except Exception as e:
        print(f"Error al enviar el correo: {e}")

@app.route('/')
def home():
    if 'usuario' not in session:
        return redirect(url_for('login'))
    return redirect(url_for('pagina_principal'))

@app.route('/registro', methods=['GET', 'POST'])
def registro():
    if request.method == 'POST':
        usuario = request.form['usuario']
        email = request.form['email']
        contrasena = request.form['contrasena']

        # Verificar si el correo ya está registrado
        conn = get_db_connection()
        existing_user = conn.execute('SELECT * FROM usuarios WHERE email = ?', (email,)).fetchone()
        
        if existing_user:
            conn.close()
            flash("El correo electrónico ya está registrado.")
            return redirect(url_for('registro'))

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
        return redirect(url_for('pagina_principal'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        usuario = request.form['usuario']
        contrasena = request.form['contrasena']

        # Buscar al usuario en la base de datos
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM usuarios WHERE usuario = ?', (usuario,)).fetchone()
        conn.close()
        
        # Verificar si las credenciales son correctas
        if user and user['contrasena'] and bcrypt.check_password_hash(user['contrasena'], contrasena):
            session['usuario'] = usuario
            return redirect(url_for('pagina_principal'))
        else:
            flash("Usuario o contraseña incorrectos.")
            return render_template('login.html')

    return render_template('login.html')

@app.route('/pagina_principal')
def pagina_principal():
    if 'usuario' not in session:
        return redirect(url_for('login'))
    return render_template('dashboard.html', usuario=session['usuario'])

@app.route('/mi_perfil')
def mi_perfil():
    if 'usuario' not in session:
        return redirect(url_for('login'))
    
    usuario = session['usuario']
    conn = get_db_connection()
    user_data = conn.execute('SELECT * FROM usuarios WHERE usuario = ?', (usuario,)).fetchone()
    conn.close()
    
    if user_data:
        return render_template('mi_perfil.html', usuario=user_data['usuario'], email=user_data['email'])
    else:
        return redirect(url_for('login'))

@app.route('/recuperar_contrasena', methods=['GET', 'POST'])
def recuperar_contrasena():
    if request.method == 'POST':
        email = request.form['email']
        
        conn = get_db_connection()
        usuario = conn.execute('SELECT * FROM usuarios WHERE email = ?', (email,)).fetchone()
        conn.close()

        if usuario:
            token = serializer.dumps(email, salt='password-reset-salt')
            enlace = url_for('restablecer_contrasena', token=token, _external=True)
            asunto = "Recuperación de contraseña"
            cuerpo = f"""
            <p>Hola, hemos recibido una solicitud para restablecer tu contraseña.</p>
            <p>Si no has solicitado este cambio, ignora este mensaje.</p>
            <p>Para restablecer tu contraseña, haz clic en el siguiente enlace:</p>
            <a href="{enlace}">Restablecer contraseña</a>
            """
            enviar_email(email, asunto, cuerpo)
            flash("Te hemos enviado un correo para recuperar tu contraseña.", "success")
        else:
            flash("El correo electrónico no está registrado.", "error")

    return render_template('recuperar_contrasena.html')

@app.route('/restablecer_contrasena/<token>', methods=['GET', 'POST'])
def restablecer_contrasena(token):
    try:
        email = serializer.loads(token, salt='password-reset-salt', max_age=3600)
    except:
        flash("El enlace de restablecimiento ha caducado o es inválido.", "error")
        return redirect(url_for('recuperar_contrasena'))

    if request.method == 'POST':
        nueva_contrasena = request.form['nueva_contrasena']
        hashed_password = bcrypt.generate_password_hash(nueva_contrasena).decode('utf-8')
        
        conn = get_db_connection()
        conn.execute('UPDATE usuarios SET contrasena = ? WHERE email = ?', (hashed_password, email))
        conn.commit()
        conn.close()
        
        flash("Tu contraseña ha sido restablecida con éxito.", "success")
        return redirect(url_for('login'))

    return render_template('restablecer_contrasena.html')

@app.route('/logout')
def logout():
    session.pop('usuario', None)
    return redirect(url_for('login'))

@app.route('/debug/routes')
def show_routes():
    """Mostrar todas las rutas disponibles para depuración"""
    routes = []
    for rule in app.url_map.iter_rules():
        routes.append({
            'endpoint': rule.endpoint,
            'methods': list(rule.methods),
            'rule': rule.rule
        })
    
    output = "<h1>Rutas disponibles:</h1><ul>"
    for route in routes:
        output += f"<li><strong>{route['rule']}</strong> - {route['endpoint']} - {route['methods']}</li>"
    output += "</ul>"
    return output

@app.route('/debug/oauth')
def debug_oauth():
    """Debug de configuración OAuth"""
    return {
        'client_id': GOOGLE_CLIENT_ID,
        'redirect_uri': GOOGLE_REDIRECT_URI,
        'auth_url': f'https://accounts.google.com/o/oauth2/v2/auth?client_id={GOOGLE_CLIENT_ID}&redirect_uri={urllib.parse.quote(GOOGLE_REDIRECT_URI)}&scope=https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/userinfo.profile openid&response_type=code&access_type=offline&prompt=consent'
    }


if __name__ == '__main__':
    app.run(debug=True)
