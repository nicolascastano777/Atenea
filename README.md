# 🤖 Atenea - Chat Assistant

Aplicación web de chat con inteligencia artificial integrada con n8n y Google Gemini.

## 📋 Características

- ✅ **Autenticación con Google OAuth**
- ✅ **Chat en tiempo real** con IA
- ✅ **Interfaz moderna** y responsiva
- ✅ **Integración con n8n** webhook
- ✅ **Base de datos SQLite** para usuarios
- ✅ **Logo personalizado** en toda la aplicación
- ✅ **Diseño azul** consistente

## 🚀 Instalación

1. **Clonar el repositorio**
```bash
git clone https://github.com/nicolascastano777/Atenea.git
cd Atenea
```

2. **Instalar dependencias**
```bash
pip install flask flask-bcrypt requests
```

3. **Ejecutar la aplicación**
```bash
python app.py
```

## 📁 Estructura del Proyecto

```
Atenea/
├── app.py                          # Aplicación Flask principal
├── usuarios.db                     # Base de datos SQLite
├── client_secret_*.json           # Credenciales Google OAuth
├── static/
│   └── images/
│       └── logo2.png              # Logo de Atenea
└── templates/
    ├── AteneaChat.html            # Interfaz principal del chat
    └── login.html                 # Página de inicio de sesión
```

## 🔧 Configuración n8n

El workflow debe incluir:

1. **Webhook Node**: Recibe mensajes del chat
2. **AI Agent**: Procesa con Google Gemini
3. **Response Node**: Devuelve la respuesta

### Formato de datos esperado:
```json
{
  "chatInput": "mensaje del usuario",
  "message": "mensaje del usuario",
  "userId": "nombre_usuario",
  "sessionId": "session_id"
}
```

## 🌐 Rutas Principales

- `/` - Redirige al chat si está autenticado
- `/login` - Página de inicio de sesión
- `/pagina_principal` - Chat principal de Atenea
- `/logout` - Cerrar sesión