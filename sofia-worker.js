const ALLOWED_ORIGIN = "https://dcgrin07-ux.github.io";
const FIREBASE_PROJECT_ID = "mygymlacima";

const RATE_LIMIT_MAX = 20;
const RATE_LIMIT_WINDOW_MS = 60 * 1000;

const rateMap = new Map();

function corsHeaders() {
  return {
    "Access-Control-Allow-Origin": ALLOWED_ORIGIN,
    "Access-Control-Allow-Headers": "Authorization, Content-Type",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Vary": "Origin"
  };
}

function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      ...corsHeaders(),
      ...extraHeaders
    }
  });
}

function getBearerToken(request) {
  const header = request.headers.get("Authorization") || "";

  if (!header.startsWith("Bearer ")) {
    return null;
  }

  const token = header.slice(7).trim();
  return token || null;
}

function decodeJwtPayload(token) {
  try {
    const parts = token.split(".");

    if (parts.length !== 3) {
      return null;
    }

    const base64 = parts[1]
      .replace(/-/g, "+")
      .replace(/_/g, "/");

    const padded =
      base64 + "=".repeat((4 - (base64.length % 4)) % 4);

    const binary = atob(padded);

    let text = "";

    for (let i = 0; i < binary.length; i++) {
      text += String.fromCharCode(binary.charCodeAt(i));
    }

    return JSON.parse(text);

  } catch {
    return null;
  }
}

async function verificarUsuario(idToken) {

  const payload = decodeJwtPayload(idToken);

  if (!payload || !payload.sub || !payload.exp) {
    return {
      ok: false,
      status: 401,
      error: "Token de Firebase inválido."
    };
  }

  const ahora = Math.floor(Date.now() / 1000);

  if (payload.exp <= ahora) {
    return {
      ok: false,
      status: 401,
      error: "La sesión de Firebase expiró."
    };
  }

  if (payload.aud !== FIREBASE_PROJECT_ID) {
    return {
      ok: false,
      status: 401,
      error: "Token no válido para este proyecto."
    };
  }

  if (
    payload.iss !==
    `https://securetoken.google.com/${FIREBASE_PROJECT_ID}`
  ) {
    return {
      ok: false,
      status: 401,
      error: "Emisor de token no válido."
    };
  }

  const uid = payload.sub;

  const url =
    `https://firestore.googleapis.com/v1/projects/` +
    `${FIREBASE_PROJECT_ID}/databases/(default)/documents/` +
    `usuarios/${encodeURIComponent(uid)}`;

  const response = await fetch(url, {
    method: "GET",
    headers: {
      "Authorization": `Bearer ${idToken}`
    }
  });

  if (response.status === 401) {
    return {
      ok: false,
      status: 401,
      error: "Firebase rechazó el token."
    };
  }

  if (response.status === 403) {
    return {
      ok: false,
      status: 403,
      error: "Firebase no permite acceder al usuario."
    };
  }

  if (response.status === 404) {
    return {
      ok: false,
      status: 403,
      error: "La cuenta no está registrada en MI GYM."
    };
  }

  if (!response.ok) {
    return {
      ok: false,
      status: 502,
      error: "No se pudo verificar el usuario en Firebase."
    };
  }

  const doc = await response.json();
  const fields = doc.fields || {};

  const autorizado =
    fields.autorizado?.booleanValue === true;

  const rol =
    fields.rol?.stringValue || "cliente";

  const email =
    fields.email?.stringValue || "";

  return {
    ok: true,
    uid,
    email,
    rol,
    autorizado
  };
}

function comprobarLimite(uid) {

  const ahora = Date.now();
  const actual = rateMap.get(uid);

  if (
    !actual ||
    ahora - actual.inicio >= RATE_LIMIT_WINDOW_MS
  ) {
    rateMap.set(uid, {
      inicio: ahora,
      cantidad: 1
    });

    return {
      permitido: true,
      restantes: RATE_LIMIT_MAX - 1
    };
  }

  if (actual.cantidad >= RATE_LIMIT_MAX) {

    const espera = Math.ceil(
      (
        RATE_LIMIT_WINDOW_MS -
        (ahora - actual.inicio)
      ) / 1000
    );

    return {
      permitido: false,
      espera
    };
  }

  actual.cantidad++;

  return {
    permitido: true,
    restantes: RATE_LIMIT_MAX - actual.cantidad
  };
}

export default {

  async fetch(request) {

    const origin = request.headers.get("Origin");

    if (
      origin &&
      origin !== ALLOWED_ORIGIN
    ) {
      return json(
        {
          ok: false,
          error: "Origen no permitido."
        },
        403
      );
    }

    if (request.method === "OPTIONS") {

      return new Response(null, {
        status: 204,
        headers: corsHeaders()
      });
    }

    const url = new URL(request.url);

    if (
      request.method === "GET" &&
      url.pathname === "/health"
    ) {

      return json({
        ok: true,
        servicio: "sofia-mi-gym",
        estado: "activo",
        proveedorIA: "no configurado"
      });
    }

    if (
      request.method !== "POST" ||
      url.pathname !== "/sofia"
    ) {

      return json(
        {
          ok: false,
          error: "Ruta no encontrada."
        },
        404
      );
    }

    const idToken =
      getBearerToken(request);

    if (!idToken) {

      return json(
        {
          ok: false,
          error:
            "Falta el token de autenticación de Firebase."
        },
        401
      );
    }

    let usuario;

    try {

      usuario =
        await verificarUsuario(idToken);

    } catch (error) {

      console.error(
        "Error verificando Firebase:",
        error
      );

      return json(
        {
          ok: false,
          error:
            "No se pudo verificar la sesión."
        },
        502
      );
    }

    if (!usuario.ok) {

      return json(
        {
          ok: false,
          error: usuario.error
        },
        usuario.status
      );
    }

    if (
      !usuario.autorizado &&
      usuario.rol !== "admin"
    ) {

      return json(
        {
          ok: false,
          error:
            "La cuenta todavía no está autorizada para usar Sofía."
        },
        403
      );
    }

    const limite =
      comprobarLimite(usuario.uid);

    if (!limite.permitido) {

      return json(
        {
          ok: false,
          error:
            "Límite temporal de consultas alcanzado.",
          retryAfterSeconds:
            limite.espera
        },
        429,
        {
          "Retry-After":
            String(limite.espera)
        }
      );
    }

    let body;

    try {

      const raw =
        await request.text();

      if (raw.length > 32000) {

        return json(
          {
            ok: false,
            error:
              "La solicitud es demasiado grande."
          },
          413
        );
      }

      body =
        JSON.parse(raw);

    } catch {

      return json(
        {
          ok: false,
          error: "JSON inválido."
        },
        400
      );
    }

    const message =
      typeof body.message === "string"
        ? body.message.trim()
        : "";

    if (!message) {

      return json(
        {
          ok: false,
          error:
            "Falta el mensaje para Sofía."
        },
        400
      );
    }

    if (message.length > 8000) {

      return json(
        {
          ok: false,
          error:
            "El mensaje supera el límite permitido."
        },
        413
      );
    }

    return json(
      {
        ok: false,
        code: "AI_PROVIDER_NOT_CONFIGURED",
        error:
          "Sofía está preparada, pero el proveedor de IA todavía no está configurado.",
        usuario: {
          uid: usuario.uid,
          rol: usuario.rol
        }
      },
      503
    );
  }
};
