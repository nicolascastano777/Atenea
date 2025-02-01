from flask import Flask, request, render_template, redirect, url_for, session, flash
from flask_bcrypt import Bcrypt
from pymongo import MongoClient
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
from itsdangerous import URLSafeTimedSerializer as Serializer
from flask_dance.contrib.google import make_google_blueprint, google
import os
import pathlib

app = Flask(__name__)
bcrypt = Bcrypt(app)

# Permitir OAuth en HTTP (Solo en desarrollo)
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

# Clave secreta para sesiones
app.secret_key = "advpjsh"

# Configuración de MongoDB Atlas
client = MongoClient("enlace de tu base de datos aquí")
db = client['nombre de tu base de datos aquí']
collection = db['nombre de tu colección aquí']

# Configuración de SendGrid
SENDGRID_API_KEY = 'enlace de la API de SendGrid aquí'

# Serializador para crear y verificar tokens
serializer = Serializer(app.secret_key, salt='password-reset-salt')

# Configuración de Google OAuth
# Configurar el blueprint correctamente
google_bp = make_google_blueprint(
    client_id='ID del cliente aquí',
    client_secret='secreto del cliente aquí',
    redirect_to='google_login_callback',
    scope=[
        "openid", 
        "https://www.googleapis.com/auth/userinfo.profile",
        "https://www.googleapis.com/auth/userinfo.email"
    ]  # Google ahora requiere estos valores exactos
)


app.register_blueprint(google_bp, url_prefix="/google_login")  # <-- Flask-Dance usa "/google_login/google/authorized"

@app.route('/login_google')
def login_google():
    # Redirige a Google para la autenticación
    return redirect(url_for('google.login'))

# Función para enviar correos
def enviar_email(destinatario, asunto, cuerpo):
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
        if collection.find_one({'email': email}):
            flash("El correo electrónico ya está registrado.")
            return redirect(url_for('registro'))

        # Hashear la contraseña
        hashed_password = bcrypt.generate_password_hash(contrasena).decode('utf-8')

        # Insertar usuario en la base de datos
        collection.insert_one({
            'usuario': usuario,
            'email': email,
            'contrasena': hashed_password
        })
        
        session['usuario'] = usuario
        return redirect(url_for('pagina_principal'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        usuario = request.form['usuario']
        contrasena = request.form['contrasena']

        # Buscar al usuario en la base de datos
        user = collection.find_one({'usuario': usuario})
        
        # Verificar si las credenciales son correctas
        if user and bcrypt.check_password_hash(user['contrasena'], contrasena):
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
    return render_template('index.html', usuario=session['usuario'])

@app.route('/mi_perfil')
def mi_perfil():
    if 'usuario' not in session:
        return redirect(url_for('login'))
    
    usuario = session['usuario']
    user_data = collection.find_one({'usuario': usuario})
    return render_template('mi_perfil.html', usuario=user_data['usuario'], email=user_data['email'])

@app.route('/recuperar_contrasena', methods=['GET', 'POST'])
def recuperar_contrasena():
    if request.method == 'POST':
        email = request.form['email']
        usuario = collection.find_one({'email': email})

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
        collection.update_one({'email': email}, {'$set': {'contrasena': hashed_password}})
        flash("Tu contraseña ha sido restablecida con éxito.", "success")
        return redirect(url_for('login'))

    return render_template('restablecer_contrasena.html')

@app.route('/logout')
def logout():
    session.pop('usuario', None)
    return redirect(url_for('login'))

# Rutas de Google OAuth
# Rutas de Google OAuth
@app.route('/google_login/callback')
def google_login_callback():
    # Si el usuario ya está autenticado, redirigirlo a la página principal
    if 'usuario' in session:
        return redirect(url_for('pagina_principal'))

    if not google.authorized:
        return redirect(url_for('google.login'))

    resp = google.get('https://www.googleapis.com/oauth2/v3/userinfo')
    
    if not resp.ok:
        flash("Error al obtener información de Google. Intenta nuevamente.", "error")
        return redirect(url_for('login'))

    user_info = resp.json()

    # 🔍 Imprimir la respuesta para depuración
    print("Respuesta de Google:", user_info)

    # Verificar que Google haya enviado un email
    if 'email' not in user_info:
        flash("Error: Google no proporcionó un email.", "error")
        return redirect(url_for('login'))

    # Obtener el ID único de Google
    google_id = user_info.get("sub")

    # Verificar si el usuario ya está registrado
    user = collection.find_one({'email': user_info['email']})
    if not user:
        # Registrar nuevo usuario con Google
        collection.insert_one({
            'usuario': user_info.get('name', 'Usuario sin nombre'),
            'email': user_info['email'],
            'google_id': google_id  # Guardamos el ID único de Google
        })

    # Iniciar sesión guardando el nombre en la sesión
    session['usuario'] = user_info.get('name', 'Usuario sin nombre')

   
    return redirect(url_for('pagina_principal'))



if __name__ == '__main__':
    app.run(debug=True)
