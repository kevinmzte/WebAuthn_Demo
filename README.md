# WebAuthn_Demo
WebAuthn Demo (Passwordless con Passkeys)
Demo mínima de registro e inicio de sesión sin contraseñas usando WebAuthn / Passkeys con:
Backend: Node.js + @simplewebauthn/server + Expres
Frontend: HTML + JS + @simplewebauthn/browser
Túnel HTTPS (recomendado): ngrok
- Incluye validación de username único, múltiples credenciales por usuario, y logs claros de verificación.

📦 Requisitos
Node.js 18+ (recomendado 18 LTS o 20+)
npm 8+
ngrok (o equivalente) para exponer HTTPS público
WebAuthn exige HTTPS (excepto http://localhost en algunos navegadores de escritorio).
Un navegador compatible:
  -Chrome/Edge/Brave (desktop y Android)
  -Safari (iOS/macOS)
  -Firefox (desktop; soporte móvil limitado para WebAuthn)
