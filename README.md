# WebAuthn_Demo
WebAuthn Demo (Passwordless con Passkeys)
Demo mínima de registro e inicio de sesión sin contraseñas usando WebAuthn / Passkeys con:
Backend: Node.js + @simplewebauthn/server + Expres
Frontend: HTML + JS + @simplewebauthn/browser
Túnel HTTPS (recomendado): ngrok
- Incluye validación de username único, múltiples credenciales por usuario, y logs claros de verificación.

# 📦 Requisitos
Node.js 18+ (recomendado 18 LTS o 20+)
npm 8+
ngrok (o equivalente) para exponer HTTPS público
WebAuthn exige HTTPS (excepto http://localhost en algunos navegadores de escritorio).
Un navegador compatible:
  -Chrome/Edge/Brave (desktop y Android)
  -Safari (iOS/macOS)
  -Firefox (desktop; soporte móvil limitado para WebAuthn)
  
# 🌐 Configuración de dominio (RP ID / Origin)
RP ID y Origin deben coincidir con la URL real desde donde se carga el frontend.
Opción A) Con ngrok (recomendado para móviles)
En otra terminal(la de ngrok si es posible)
ngrok http 3000

Copiá la URL pública (por ej. https://tu-subdominio.ngrok-free.dev).
Asegurate de que en server.js:
rpID = 'tu-subdominio.ngrok-free.dev' (sin https://)
origin = 'https://tu-subdominio.ngrok-free.dev'
Opción B) Localhost (solo desktop)
rpID = 'localhost'
origin = 'http://localhost:3000'
Para Android/iOS probando desde el teléfono, usá ngrok (los móviles necesitan HTTPS real y un dominio alcanzable).

# ▶️ Ejecución
Iniciar el servidor(bash)
node server.js

Abrí en el navegador la URL correspondiente:
Con ngrok: https://tu-subdominio.ngrok-free.dev
Localhost: http://localhost:3000
