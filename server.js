// server.js
// helper para normalizar varios formatos a Buffer
function toBuffer(input) {
  if (Buffer.isBuffer(input)) return input;
  if (typeof input === 'string') return base64url.toBuffer(input); // espera base64url
  if (input instanceof ArrayBuffer) return Buffer.from(new Uint8Array(input));
  if (ArrayBuffer.isView(input)) return Buffer.from(input.buffer, input.byteOffset, input.byteLength);
  return Buffer.from(input);
}

const express = require('express');
const path = require('path');
const { v4: uuidv4 } = require('uuid');
const base64url = require('base64url');
// username -> { userId, challenge, createdAt }
const pendingRegs = new Map();

const {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} = require('@simplewebauthn/server');

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

/** ===================== CONFIG ===================== */
const rpName = 'FP-UNA Demo';
const rpID = 'localhost';
const origin = 'http://localhost:3000';
//const rpID = 'postacetabular-gilbert-industriously.ngrok-free.dev';
//const origin = 'https://postacetabular-gilbert-industriously.ngrok-free.dev';

/** ===================== "DB" en memoria ===================== */
const users = new Map();         // username -> { id<string>, username }
const credentials = new Map();   // userId -> [ { credentialID<Buffer>, publicKey<Buffer>, counter<number>, deviceType<string> } ]
const challenges = new Map();    // userId -> lastChallenge<string>

/** Helpers */
function getOrCreateUser(username) {
  let user = [...users.values()].find(u => u.username === username);
  if (!user) {
    user = { id: uuidv4(), username };
    users.set(user.id, user);
  }
  return user;
}

function getUserByUsername(username) {
  const query = String(username).trim().toLowerCase();
  return [...users.values()].find(u => u.username.toLowerCase() === query);
}

function getUserCreds(userId) {
  return credentials.get(userId) || [];
}

/** ===================== REGISTRO ===================== */
app.post('/webauthn/register/start', async (req, res) => {
  try {
    const { username } = req.body;

    if (!username || typeof username !== 'string' || !username.trim()) {
      return res.status(400).json({ ok: false, msg: 'username requerido' });
    }

    // Si YA existe en usuarios definitivos → bloquear (Opción A: usernames únicos)
    const existing = getUserByUsername(username);
    if (existing) {
      return res.status(409).json({ ok: false, msg: 'username ya existe' });
    }

    // Generar un userId temporal para esta tentativa
    const tempUserId = uuidv4();
    const userIdBuf  = Buffer.from(tempUserId, 'utf8');

    const opts = await generateRegistrationOptions({
      rpName,
      rpID,
      userID: userIdBuf,
      userName: username.trim(),
      userDisplayName: username.trim(),
      attestationType: 'none',
      authenticatorSelection: {
        residentKey: 'preferred',
        userVerification: 'required',
        // authenticatorAttachment: 'platform', // si querés limitar al dispositivo actual
      },
      supportedAlgorithmIDs: [-7, -257],
    });

    // Guardar intento PENDIENTE (no creamos user todavía)
    pendingRegs.set(username.trim(), {
      userId: tempUserId,
      challenge: opts.challenge,
      createdAt: Date.now(),
    });

    return res.json(opts);
  } catch (err) {
    console.error('❌ Error en /webauthn/register/start:', err);
    return res.status(500).json({ ok: false, msg: 'internal error' });
  }
});

app.post('/webauthn/register/finish', async (req, res) => {
  try {
    const { username, attestationResponse } = req.body;
    const norm = String(username || '').trim();

    // Debe existir un registro pendiente para ese username
    const pending = pendingRegs.get(norm);
    if (!pending) {
      return res.status(400).json({ ok: false, msg: 'no hay registro pendiente para este username' });
    }

    const verification = await verifyRegistrationResponse({
      response: attestationResponse,
      expectedChallenge: pending.challenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
    });

    if (!verification.verified) {
      // limpiar pending para permitir reintento limpio
      pendingRegs.delete(norm);
      return res.json({ ok: false });
    }

    // Sólo ahora creamos el usuario definitivo con el userId TEMPORAL
    const user = { id: pending.userId, username: norm };
    users.set(user.id, user);

    // Guardar credencial
    const info = verification.registrationInfo || {};
    const credential = info.credential || {};
    if (!credential.id || !credential.publicKey) {
      pendingRegs.delete(norm);
      return res.status(400).json({ ok: false, msg: 'Credencial inválida' });
    }

    const credIdBuf  = base64url.toBuffer(credential.id);
    const pubKeyBuf  = Buffer.from(credential.publicKey);
    const regCounter = Number(info.counter ?? credential.counter ?? 0);

    const list = getUserCreds(user.id);
    if (!list.find(c => c.credentialID.equals(credIdBuf))) {
      list.push({
        credentialID: credIdBuf,
        credentialPublicKey: pubKeyBuf,
        counter: regCounter,
        deviceType: info.credentialDeviceType,
        transports: credential.transports,
        backedUp: info.credentialBackedUp,
      });
      credentials.set(user.id, list);
    }

    // limpiar pending (registro exitoso)
    pendingRegs.delete(norm);

    console.log(`- Credencial registrada para ${norm}: ${base64url.encode(credIdBuf)}`);
    return res.json({ ok: true });
  } catch (e) {
    console.error('❌ Error en registro:', e);
    return res.status(400).json({ ok: false, msg: 'verification failed' });
  }
});

/** ===================== LOGIN ===================== */
app.post('/webauthn/login/start', async (req, res) => {
  try {
    const { username } = req.body;

    // Validación básica
    if (!username || typeof username !== 'string' || !username.trim()) {
      return res.status(422).json({ ok: false, msg: 'username requerido' });
    }

    const user = getUserByUsername(username);
    // 404: usuario no encontrado
    if (!user) {
      return res.status(404).json({ ok: false, msg: 'Usuario no encontrado' });
    }

    const userCreds = getUserCreds(user.id) || [];
    // 404: usuario sin credenciales registradas
    if (userCreds.length === 0) {
      return res.status(404).json({ ok: false, msg: 'El usuario no tiene credenciales registradas' });
    }

    // Construir allowCredentials (podés quitar el filtro si querés aceptar todos)
    const allowCredentials = userCreds
      .filter(c => !c.deviceType || c.deviceType === 'platform')
      .map(c => ({
        id: base64url.encode(c.credentialID),
        type: 'public-key',
        transports: c.transports,
      }));

    // Si el filtro dejó vacío, devolvemos 404 coherente para el frontend
    if (allowCredentials.length === 0) {
      return res.status(404).json({ ok: false, msg: 'No hay credenciales compatibles para este dispositivo' });
    }

    const opts = await generateAuthenticationOptions({
      rpID,
      userVerification: 'required',
      allowCredentials,
    });

    challenges.set(user.id, opts.challenge);
    return res.json(opts);
  } catch (err) {
    console.error('❌ Error en /webauthn/login/start:', err);
    return res.status(500).json({ ok: false, msg: 'internal error' });
  }
});


app.post('/webauthn/login/finish', async (req, res) => {
  const { username, assertionResponse } = req.body;
  const user = getUserByUsername(username);
  if (!user) return res.status(400).json({ ok: false, msg: 'user no encontrado' });

  const creds = getUserCreds(user.id);

  // El cliente puede enviar rawId (ArrayBuffer) o id (base64url string).
  // Intentamos obtener un Buffer correcto en ambos casos.
  let credIdBuf;
  try {
    if (assertionResponse.rawId) {
      // rawId normalmente llega como base64url-encoded ArrayBuffer en JSON; 
      // si viene como un objeto ArrayBuffer / TypedArray desde el browser, puede requerir conversión.
      // Intentamos detectar y convertir con base64url.toBuffer si es string, o Buffer.from si es ArrayBuffer-like.
      if (typeof assertionResponse.rawId === 'string') {
        // a veces viene string base64url
        credIdBuf = base64url.toBuffer(assertionResponse.rawId);
      } else if (assertionResponse.rawId instanceof ArrayBuffer) {
        credIdBuf = Buffer.from(new Uint8Array(assertionResponse.rawId));
      } else if (ArrayBuffer.isView(assertionResponse.rawId)) {
        credIdBuf = Buffer.from(assertionResponse.rawId.buffer, assertionResponse.rawId.byteOffset, assertionResponse.rawId.byteLength);
      } else {
        // fallback
        credIdBuf = base64url.toBuffer(assertionResponse.id);
      }
    } else {
      // fallback a assertionResponse.id (string base64url)
      credIdBuf = base64url.toBuffer(assertionResponse.id);
    }
  } catch (err) {
    console.error('❌ Error convirtiendo id de la assertion:', err);
    return res.status(400).json({ ok: false, msg: 'invalid assertion id' });
  }

  const authenticator = creds.find(c => c.credentialID.equals(credIdBuf));

  console.log('Credenciales guardadas:', creds.map(c => base64url.encode(c.credentialID)));
  console.log('ID recibido (decoded):', base64url.encode(credIdBuf));
  console.log('Autenticador encontrado:', !!authenticator);

  if (!authenticator) {
    console.log('❌ No matching credential found for login');
    return res.status(400).json({ ok: false, msg: 'No matching credential found' });
  }

  console.log('Autenticador cargado:', {
    credentialID: base64url.encode(authenticator.credentialID),
    tienePublicKey: !!authenticator.credentialPublicKey,
    counter: authenticator.counter,
  });

    // Validaciones extra antes de llamar a verifyAuthenticationResponse
    if (!authenticator.credentialPublicKey) {
      console.error('❌ authenticator missing public key');
      return res.status(400).json({ ok: false, msg: 'Authenticator missing public key' });
    }
    if (typeof authenticator.counter !== 'number') {
      console.error('❌ authenticator counter not a number:', authenticator.counter);
      return res.status(400).json({ ok: false, msg: 'Authenticator counter invalid' });
    }
    console.log('Antes de verificar: tipos de datos');
    console.log('credentialID type:', typeof authenticator.credentialID);
    console.log('credentialPublicKey type:', typeof authenticator.credentialPublicKey);

    function ensureBuffer(value, label) {
      if (Buffer.isBuffer(value)) return value;
      if (typeof value === 'string') {
        console.log(`  ${label}: convirtiendo de string → Buffer`);
        return base64url.toBuffer(value);
      }
      if (value instanceof Uint8Array) {
        console.log(`  ${label}: convirtiendo de Uint8Array → Buffer`);
        return Buffer.from(value);
      }
      if (value?.data && Array.isArray(value.data)) {
        // caso típico si el Buffer fue serializado con JSON.stringify()
        console.log(`  ${label}: convirtiendo de objeto {data:[]} → Buffer`);
        return Buffer.from(value.data);
      }
      console.warn(`  ${label}: formato no reconocido, devolviendo valor sin cambios`);
      return value;
    }

    authenticator.credentialID = ensureBuffer(authenticator.credentialID, 'credentialID');
    authenticator.credentialPublicKey = ensureBuffer(authenticator.credentialPublicKey, 'credentialPublicKey');

    console.log('Después de conversión:');
    console.log('credentialID instanceof Buffer:', authenticator.credentialID instanceof Buffer);
    console.log('credentialPublicKey instanceof Buffer:', authenticator.credentialPublicKey instanceof Buffer);
    console.log('Objeto que se enviará a verifyAuthenticationResponse:');
    console.dir({
      credentialID: authenticator.credentialID,
      credentialPublicKey: authenticator.credentialPublicKey,
      counter: authenticator.counter,
      transports: authenticator.transports,
    }, { depth: null });

  try {
    const verification = await verifyAuthenticationResponse({
      response: assertionResponse,
      expectedChallenge: challenges.get(user.id),
      expectedOrigin: origin,
      expectedRPID: rpID,
      // v11+ espera "credential", no "authenticator"
      credential: {
        id: authenticator.credentialID,                 // antes: credentialID
        publicKey: authenticator.credentialPublicKey,   // antes: credentialPublicKey
        counter: authenticator.counter,
        transports: authenticator.transports || ['internal'],
      },
    });

    if (!verification.verified) {
      return res.json({ ok: false });
    }

    authenticator.counter = verification.authenticationInfo.newCounter;
    credentials.set(user.id, creds);

    console.log(`✅ Login verificado para ${username}`);
    res.json({ ok: true });
  } catch (e) {
    console.error('❌ Error en login:', e);
    res.status(400).json({ ok: false, msg: 'verification failed' });
  }
});

/** ===================== SERVER ===================== */
const PORT = 3000;
app.listen(PORT, () => {
  console.log(`WebAuthn demo corriendo en ${origin}`);
});
