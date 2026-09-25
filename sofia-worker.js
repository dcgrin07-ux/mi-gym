/**
 * SOFIA WORKER — MI GYM LA CIMA
 * Backend seguro de Sofía IA
 *
 * - Autenticación mediante Firebase ID Token
 * - Verificación de autorización en Firestore
 * - Control básico de solicitudes
 * - CORS restringido al sitio de MI GYM
 * - Workers AI como proveedor de IA
 * - Sin API keys de IA en el frontend
 */

const ALLOWED_ORIGIN = "https://dcgrin07-ux.github.io";
const FIREBASE_PROJECT_ID = "mygymlacima";

const AI_MODEL = "@cf/zai-org/glm-4.7-flash";

const RATE_LIMIT_MAX = 20;
const RATE_LIMIT_WINDOW_MS = 60 * 1000;

const rateMap = new Map();

/* ============================================================
   CORS
   ============================================================ */

function corsHeaders() {
  return {
    "Access-Control-Allow-Origin": ALLOWED_ORIGIN,
    "Access-Control-Allow-Headers": "Authorization, Content-Type",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Vary": "Origin"
  };
}

/* ============================================================
   RESPUESTAS JSON
   ============================================================ */

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

/* ============================================================
   TOKEN FIREBASE
   ============================================================ */

function getBearerToken(request) {
  const header = request.headers.get("Authorization") || "";

  if (!header.startsWith("Bearer ")) {
    return null;
  }

  const token = header.slice(7).trim();

  return token || null;
}

/* ============================================================
   RATE LIMIT
   ============================================================ */

function checkRateLimit(uid) {
  const now = Date.now();
  const current = rateMap.get(uid);

  if (
    !current ||
    now - current.startedAt >= RATE_LIMIT_WINDOW_MS
  ) {
    rateMap.set(uid, {
      startedAt: now,
      count: 1
    });

    return {
      allowed: true,
      remaining: RATE_LIMIT_MAX - 1
    };
  }

  if (current.count >= RATE_LIMIT_MAX) {
    const retryAfter = Math.ceil(
      (RATE_LIMIT_WINDOW_MS -
        (now - current.startedAt)) /
        1000
    );

    return {
      allowed: false,
      retryAfter
    };
  }

  current.count += 1;

  return {
    allowed: true,
    remaining:
      RATE_LIMIT_MAX - current.count
  };
}

/* ============================================================
   DECODIFICAR JWT FIREBASE
   ============================================================ */

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
      base64 +
      "=".repeat(
        (4 - (base64.length % 4)) % 4
      );

    const binary = atob(padded);

    let text = "";

    for (let i = 0; i < binary.length; i++) {
      text += String.fromCharCode(
        binary.charCodeAt(i)
      );
    }

    return JSON.parse(text);

  } catch {
    return null;
  }
}

/* ============================================================
   VERIFICAR USUARIO EN FIREBASE
   ============================================================ */

async function getUserFromFirebase(idToken) {

  const payload =
    decodeJwtPayload(idToken);

  if (
    !payload ||
    !payload.sub ||
    !payload.exp
  ) {
    return {
      ok: false,
      status: 401,
      error:
        "Token de Firebase inválido."
    };
  }

  const nowSeconds =
    Math.floor(Date.now() / 1000);

  if (payload.exp <= nowSeconds) {
    return {
      ok: false,
      status: 401,
      error:
        "La sesión de Firebase expiró."
    };
  }

  if (
    payload.aud !==
    FIREBASE_PROJECT_ID
  ) {
    return {
      ok: false,
      status: 401,
      error:
        "Token de Firebase no válido para este proyecto."
    };
  }

  if (
    payload.iss !==
    `https://securetoken.google.com/${FIREBASE_PROJECT_ID}`
  ) {
    return {
      ok: false,
      status: 401,
      error:
        "Emisor de token no válido."
    };
  }

  const uid = payload.sub;

  const url =
    `https://firestore.googleapis.com/v1/projects/${FIREBASE_PROJECT_ID}` +
    `/databases/(default)/documents/usuarios/${encodeURIComponent(uid)}`;

  const response = await fetch(url, {
    method: "GET",
    headers: {
      "Authorization":
        `Bearer ${idToken}`
    }
  });

  if (response.status === 401) {
    return {
      ok: false,
      status: 401,
      error:
        "Firebase rechazó el token."
    };
  }

  if (response.status === 403) {
    return {
      ok: false,
      status: 403,
      error:
        "Firebase no permite acceder al usuario."
    };
  }

  if (response.status === 404) {
    return {
      ok: false,
      status: 403,
      error:
        "La cuenta no está registrada en MI GYM."
    };
  }

  if (!response.ok) {
    return {
      ok: false,
      status: 502,
      error:
        "No se pudo verificar la autorización en Firebase."
    };
  }

  const doc =
    await response.json();

  const fields =
    doc.fields || {};

  const autorizado =
    fields.autorizado?.booleanValue === true;

  const rol =
    fields.rol?.stringValue ||
    "cliente";

  const email =
    fields.email?.stringValue ||
    "";

  return {
    ok: true,
    uid,
    email,
    rol,
    autorizado
  };
}

/* ============================================================
   CONVERTIR HISTORIAL DE MI GYM A FORMATO DEL MODELO
   ============================================================ */

function convertirHistorial(history) {

  if (!Array.isArray(history)) {
    return [];
  }

  return history
    .filter(item =>
      item &&
      typeof item === "object" &&
      typeof item.role === "string" &&
      Array.isArray(item.parts) &&
      typeof item.parts[0]?.text === "string"
    )
    .map(item => {

      let role = item.role;

      if (role === "model") {
        role = "assistant";
      }

      if (
        role !== "user" &&
        role !== "assistant"
      ) {
        return null;
      }

      return {
        role,
        content:
          item.parts[0].text
      };
    })
    .filter(Boolean);
}

/* ============================================================
   EXTRAER RESPUESTA DEL MODELO
   ============================================================ */

function extraerRespuestaIA(result) {

  if (!result) {
    return "";
  }

  /*
   * Algunos modelos/bindings pueden devolver
   * directamente una propiedad response.
   */

  if (
    typeof result.response === "string"
  ) {
    return result.response.trim();
  }

  /*
   * Formato tipo Chat Completions
   */

  const content =
    result?.choices?.[0]?.message?.content;

  if (typeof content === "string") {
    return content.trim();
  }

  /*
   * Algunas respuestas pueden utilizar text.
   */

  if (
    typeof result.text === "string"
  ) {
    return result.text.trim();
  }

  /*
   * Formato output_text
   */

  if (
    typeof result.output_text === "string"
  ) {
    return result.output_text.trim();
  }

  return "";
}

/* ============================================================
   WORKER
   ============================================================ */

export default {

  async fetch(request, env) {

    const origin =
      request.headers.get("Origin");

    /*
     * Rechazar otros sitios.
     */

    if (
      origin &&
      origin !== ALLOWED_ORIGIN
    ) {
      return json(
        {
          ok: false,
          error:
            "Origen no permitido."
        },
        403
      );
    }

    /*
     * Preflight CORS
     */

    if (
      request.method === "OPTIONS"
    ) {
      return new Response(null, {
        status: 204,
        headers: corsHeaders()
      });
    }

    const url =
      new URL(request.url);

    /* ========================================================
       HEALTH CHECK
       ======================================================== */

    if (
      request.method === "GET" &&
      url.pathname === "/health"
    ) {

      return json({
        ok: true,
        servicio: "sofia-mi-gym",
        estado: "activo",
        proveedorIA: "Cloudflare Workers AI",
        modelo: AI_MODEL
      });
    }

    /* ========================================================
       RUTA SOFIA
       ======================================================== */

    if (
      request.method !== "POST" ||
      url.pathname !== "/sofia"
    ) {

      return json(
        {
          ok: false,
          error:
            "Ruta no encontrada."
        },
        404
      );
    }

    /* ========================================================
       AUTENTICACIÓN
       ======================================================== */

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

    let user;

    try {

      user =
        await getUserFromFirebase(
          idToken
        );

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

    if (!user.ok) {

      return json(
        {
          ok: false,
          error: user.error
        },
        user.status
      );
    }

    /* ========================================================
       AUTORIZACIÓN
       ======================================================== */

    if (
      !user.autorizado &&
      user.rol !== "admin"
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

    /* ========================================================
       RATE LIMIT
       ======================================================== */

    const rate =
      checkRateLimit(user.uid);

    if (!rate.allowed) {

      return json(
        {
          ok: false,
          error:
            "Límite temporal de consultas alcanzado.",
          retryAfterSeconds:
            rate.retryAfter
        },
        429,
        {
          "Retry-After":
            String(rate.retryAfter)
        }
      );
    }

    /* ========================================================
       LEER BODY
       ======================================================== */

    let body;

    try {

      const raw =
        await request.text();

      if (raw.length > 32_000) {

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
          error:
            "JSON inválido."
        },
        400
      );
    }

    /* ========================================================
       MENSAJE ACTUAL
       ======================================================== */

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

    if (message.length > 8_000) {

      return json(
        {
          ok: false,
          error:
            "El mensaje supera el límite permitido."
        },
        413
      );
    }

    /* ========================================================
       SYSTEM PROMPT
       ======================================================== */

    const systemPrompt =
      typeof body.systemPrompt === "string" &&
      body.systemPrompt.trim()
        ? body.systemPrompt.trim()
        : `
Actuá como Sofía, asistente personal de Mi Gym La Cima.

Respondé en español argentino, de manera clara,
natural, directa y amigable.

Ayudá al usuario con entrenamiento,
hábitos, alimentación general,
progreso, descanso y recuperación.

No inventes datos.

Cuando se trate de cuestiones médicas,
síntomas o lesiones, aclarale que la
información no reemplaza la evaluación
de un profesional de la salud.
`.trim();

    /* ========================================================
       HISTORIAL
       ======================================================== */

    const history =
      convertirHistorial(
        body.history
      );

    /*
     * Evitamos que el historial crezca
     * indefinidamente.
     */

    const historialLimitado =
      history.slice(-12);

    /* ========================================================
       ARMAR MENSAJES
       ======================================================== */

    const messages = [

      {
        role: "system",
        content: systemPrompt
      },

      ...historialLimitado,

      {
        role: "user",
        content: message
      }

    ];

    /* ========================================================
       LLAMADA A CLOUDFLARE WORKERS AI
       ======================================================== */

    let aiResult;

    try {

      aiResult =
        await env.AI.run(
          AI_MODEL,
          {
            messages,
            max_tokens: 700,
            temperature: 0.7,
            user: user.uid
          },
          {
            rejectIfBusy: true
          }
        );

    } catch (error) {

      console.error(
        "Error Workers AI:",
        error
      );

      return json(
        {
          ok: false,
          code:
            "AI_PROVIDER_ERROR",
          error:
            "Sofía no pudo procesar la consulta en este momento. Probá nuevamente en unos segundos."
        },
        503
      );
    }

    /* ========================================================
       EXTRAER RESPUESTA
       ======================================================== */

    const answer =
      extraerRespuestaIA(
        aiResult
      );

    if (!answer) {

      console.error(
        "Workers AI devolvió una respuesta sin texto:",
        aiResult
      );

      return json(
        {
          ok: false,
          code:
            "AI_EMPTY_RESPONSE",
          error:
            "Sofía recibió una respuesta vacía del proveedor de IA."
        },
        502
      );
    }

    /* ========================================================
       RESPUESTA AL FRONTEND
       ======================================================== */

    return json({
      ok: true,
      answer,
      model: AI_MODEL,
      remaining:
        rate.remaining
    });
  }
};
