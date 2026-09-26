/**
 * ============================================================
 * SOFÍA WORKER — MI GYM LA CIMA
 * ============================================================
 *
 * MI GYM
 *   ↓
 * Firebase Authentication
 *   ↓
 * Cloudflare Worker
 *   ↓
 * Firebase / Firestore
 *   ↓
 * Cloudflare Workers AI
 *   ↓
 * GLM-4.7-Flash
 *
 * ============================================================
 */

const ALLOWED_ORIGIN =
  "https://dcgrin07-ux.github.io";

const FIREBASE_PROJECT_ID =
  "mygymlacima";

const AI_MODEL =
  "@cf/zai-org/glm-4.7-flash";

const RATE_LIMIT_MAX = 20;

const RATE_LIMIT_WINDOW_MS =
  60 * 1000;

const rateMap = new Map();


/* ============================================================
   CORS
   ============================================================ */

function corsHeaders() {

  return {
    "Access-Control-Allow-Origin":
      ALLOWED_ORIGIN,

    "Access-Control-Allow-Headers":
      "Authorization, Content-Type",

    "Access-Control-Allow-Methods":
      "POST, OPTIONS",

    "Vary":
      "Origin"
  };

}


/* ============================================================
   JSON
   ============================================================ */

function json(
  data,
  status = 200,
  extraHeaders = {}
) {

  return new Response(
    JSON.stringify(data),
    {
      status,

      headers: {
        "Content-Type":
          "application/json; charset=utf-8",

        ...corsHeaders(),

        ...extraHeaders
      }
    }
  );

}


/* ============================================================
   BEARER TOKEN
   ============================================================ */

function getBearerToken(request) {

  const header =
    request.headers.get("Authorization") ||
    "";

  if (!header.startsWith("Bearer ")) {
    return null;
  }

  const token =
    header.slice(7).trim();

  return token || null;

}


/* ============================================================
   RATE LIMIT
   ============================================================ */

function checkRateLimit(uid) {

  const now = Date.now();

  const current =
    rateMap.get(uid);

  if (
    !current ||
    now - current.startedAt >=
      RATE_LIMIT_WINDOW_MS
  ) {

    rateMap.set(
      uid,
      {
        startedAt: now,
        count: 1
      }
    );

    return {
      allowed: true,
      remaining:
        RATE_LIMIT_MAX - 1
    };

  }

  if (
    current.count >=
    RATE_LIMIT_MAX
  ) {

    const retryAfter =
      Math.ceil(
        (
          RATE_LIMIT_WINDOW_MS -
          (now - current.startedAt)
        ) / 1000
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
      RATE_LIMIT_MAX -
      current.count
  };

}


/* ============================================================
   DECODIFICAR JWT
   ============================================================ */

function decodeJwtPayload(token) {

  try {

    const parts =
      token.split(".");

    if (parts.length !== 3) {
      return null;
    }

    const base64 =
      parts[1]
        .replace(/-/g, "+")
        .replace(/_/g, "/");

    const padded =
      base64 +
      "=".repeat(
        (4 - (base64.length % 4)) % 4
      );

    const binary =
      atob(padded);

    let text = "";

    for (
      let i = 0;
      i < binary.length;
      i++
    ) {

      text +=
        String.fromCharCode(
          binary.charCodeAt(i)
        );

    }

    return JSON.parse(text);

  } catch {

    return null;

  }

}


/* ============================================================
   VERIFICAR USUARIO FIREBASE
   ============================================================ */

async function getUserFromFirebase(
  idToken
) {

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
    Math.floor(
      Date.now() / 1000
    );

  if (
    payload.exp <=
    nowSeconds
  ) {

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

  const uid =
    payload.sub;

  const url =
    `https://firestore.googleapis.com/v1/projects/` +
    `${FIREBASE_PROJECT_ID}` +
    `/databases/(default)/documents/usuarios/` +
    `${encodeURIComponent(uid)}`;

  const response =
    await fetch(
      url,
      {
        method: "GET",

        headers: {
          "Authorization":
            `Bearer ${idToken}`
        }
      }
    );

  if (
    response.status === 401
  ) {

    return {
      ok: false,
      status: 401,
      error:
        "Firebase rechazó el token."
    };

  }

  if (
    response.status === 403
  ) {

    return {
      ok: false,
      status: 403,
      error:
        "Firebase no permite acceder al usuario."
    };

  }

  if (
    response.status === 404
  ) {

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
   EXTRAER TEXTO DE DIFERENTES FORMATOS
   ============================================================ */

function extraerTexto(valor) {

  if (
    typeof valor === "string"
  ) {

    return valor.trim();

  }


  if (
    Array.isArray(valor)
  ) {

    return valor
      .map(item => {

        if (
          typeof item === "string"
        ) {

          return item;

        }

        if (
          item &&
          typeof item.text === "string"
        ) {

          return item.text;

        }

        if (
          item &&
          typeof item.content === "string"
        ) {

          return item.content;

        }

        return "";

      })
      .join("")
      .trim();

  }


  if (
    valor &&
    typeof valor === "object"
  ) {

    if (
      typeof valor.text === "string"
    ) {

      return valor.text.trim();

    }

    if (
      typeof valor.content === "string"
    ) {

      return valor.content.trim();

    }

  }

  return "";

}


/* ============================================================
   EXTRAER RESPUESTA DE GLM-4.7-FLASH
   ============================================================ */

function extraerRespuestaIA(
  result
) {

  if (!result) {
    return "";
  }


  /*
   * FORMATO DIRECTO
   *
   * {
   *   response: "..."
   * }
   */

  let texto =
    extraerTexto(
      result.response
    );

  if (texto) {
    return texto;
  }


  /*
   * FORMATO CHAT COMPLETIONS
   *
   * choices[0].message.content
   */

  texto =
    extraerTexto(
      result
        ?.choices
        ?. [0]
        ?.message
        ?.content
    );

  if (texto) {
    return texto;
  }


  /*
   * FORMATO ANIDADO
   */

  texto =
    extraerTexto(
      result
        ?.result
        ?.response
    );

  if (texto) {
    return texto;
  }


  texto =
    extraerTexto(
      result
        ?.result
        ?.choices
        ?. [0]
        ?.message
        ?.content
    );

  if (texto) {
    return texto;
  }


  /*
   * ALGUNOS FORMATOS PUEDEN DEVOLVER
   * EL TEXTO EN OTROS CAMPOS.
   */

  const campos = [

    result.text,

    result.output_text,

    result.result?.text,

    result.result?.output_text

  ];

  for (
    const campo of campos
  ) {

    texto =
      extraerTexto(campo);

    if (texto) {
      return texto;
    }

  }


  /*
   * IMPORTANTE:
   *
   * GLM es un modelo de razonamiento.
   * Si por alguna razón solamente devuelve
   * reasoning_content, lo usamos como último
   * recurso para no perder la respuesta.
   */

  const reasoningCampos = [

    result
      ?.choices
      ?. [0]
      ?.message
      ?.reasoning_content,

    result
      ?.result
      ?.choices
      ?. [0]
      ?.message
      ?.reasoning_content,

    result.reasoning_content,

    result.result?.reasoning_content

  ];


  for (
    const campo of reasoningCampos
  ) {

    texto =
      extraerTexto(campo);

    if (texto) {
      return texto;
    }

  }


  return "";

}


/* ============================================================
   CONSTRUIR MENSAJES
   ============================================================ */

function construirMensajes(
  body
) {

  const systemPrompt =

    typeof body.systemPrompt ===
      "string" &&
    body.systemPrompt.trim()

      ? body.systemPrompt.trim()

      : `
Sos Sofía, la asistente personal
de Mi Gym La Cima.

Respondé en español argentino.

Sé clara, natural, cálida,
directa y práctica.

No inventes datos del usuario.

Si no tenés información suficiente,
decilo claramente.

Podés ayudar con entrenamiento,
actividad física, hábitos,
recuperación, alimentación general,
progreso y utilización de la aplicación.

Cuando una consulta sea médica,
no presentes un diagnóstico
como certeza y recomendá consultar
a un profesional cuando corresponda.
`;


  const messages = [

    {
      role: "system",
      content: systemPrompt
    }

  ];


  const history =

    Array.isArray(body.history)

      ? body.history

      : [];


  const historialLimpio =

    history

      .filter(
        item =>
          item &&
          (
            item.role === "user" ||
            item.role === "assistant"
          )
      )

      .slice(-10);


  for (
    const item of historialLimpio
  ) {

    const content =

      typeof item.content ===
        "string"

        ? item.content.trim()

        : "";


    if (!content) {
      continue;
    }


    messages.push({

      role:
        item.role,

      content:
        content

    });

  }


  return messages;

}


/* ============================================================
   WORKER PRINCIPAL
   ============================================================ */

export default {

  async fetch(
    request,
    env
  ) {


    /*
     * ----------------------------------------------------------
     * CORS
     * ----------------------------------------------------------
     */

    const origin =
      request.headers.get("Origin");


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
     * ----------------------------------------------------------
     * OPTIONS
     * ----------------------------------------------------------
     */

    if (
      request.method ===
      "OPTIONS"
    ) {

      return new Response(
        null,
        {
          status: 204,
          headers:
            corsHeaders()
        }
      );

    }


    /*
     * ----------------------------------------------------------
     * URL
     * ----------------------------------------------------------
     */

    const url =
      new URL(request.url);


    /*
     * ----------------------------------------------------------
     * HEALTH
     * ----------------------------------------------------------
     */

    if (
      request.method === "GET" &&
      url.pathname === "/health"
    ) {

      return json({

        ok: true,

        servicio:
          "sofia-mi-gym",

        estado:
          "activo",

        proveedorIA:
          "Cloudflare Workers AI",

        modelo:
          AI_MODEL

      });

    }


    /*
     * ----------------------------------------------------------
     * RUTA SOFÍA
     * ----------------------------------------------------------
     */

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


    /*
     * ----------------------------------------------------------
     * TOKEN
     * ----------------------------------------------------------
     */

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


    /*
     * ----------------------------------------------------------
     * FIREBASE
     * ----------------------------------------------------------
     */

    let user;

    try {

      user =
        await getUserFromFirebase(
          idToken
        );

    } catch (error) {

      console.error(
        "ERROR FIREBASE:",
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
          error:
            user.error
        },
        user.status
      );

    }


    /*
     * ----------------------------------------------------------
     * AUTORIZACIÓN
     * ----------------------------------------------------------
     */

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


    /*
     * ----------------------------------------------------------
     * RATE LIMIT
     * ----------------------------------------------------------
     */

    const rate =
      checkRateLimit(
        user.uid
      );


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
            String(
              rate.retryAfter
            )
        }
      );

    }


    /*
     * ----------------------------------------------------------
     * LEER BODY
     * ----------------------------------------------------------
     */

    let body;

    try {

      const raw =
        await request.text();


      if (
        raw.length >
        32000
      ) {

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


    /*
     * ----------------------------------------------------------
     * MENSAJE
     * ----------------------------------------------------------
     */

    const message =

      typeof body.message ===
        "string"

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


    if (
      message.length >
      8000
    ) {

      return json(
        {
          ok: false,
          error:
            "El mensaje supera el límite permitido."
        },
        413
      );

    }


    /*
     * ----------------------------------------------------------
     * COMPROBAR IA
     * ----------------------------------------------------------
     */

    if (!env.AI) {

      return json(
        {
          ok: false,

          code:
            "AI_BINDING_MISSING",

          error:
            "El binding AI de Cloudflare no está disponible."
        },
        500
      );

    }


    /*
     * ----------------------------------------------------------
     * MENSAJES
     * ----------------------------------------------------------
     */

    const messages =
      construirMensajes(
        body
      );


    /*
     * Agregamos el mensaje actual.
     */

    messages.push({

      role:
        "user",

      content:
        message

    });


    /*
     * ----------------------------------------------------------
     * LLAMADA A GLM-4.7-FLASH
     * ----------------------------------------------------------
     *
     * CAMBIO IMPORTANTE:
     *
     * - stream: false
     * - max_completion_tokens
     * - temperature
     * - user
     *
     * Cloudflare documenta max_tokens como
     * deprecated en favor de max_completion_tokens.
     *
     * ----------------------------------------------------------
     */

    let aiResult;

    try {

      aiResult =
        await env.AI.run(
          AI_MODEL,
          {

            messages:

              messages,

            stream:
              false,

            max_completion_tokens:
              1200,

            temperature:
              0.7,

            user:
              user.uid

          },
          {

            rejectIfBusy:
              true

          }
        );


    } catch (error) {

      console.error(
        "ERROR WORKERS AI:",
        error
      );


      return json(
        {
          ok: false,

          code:
            "AI_PROVIDER_ERROR",

          error:
            "Sofía no pudo comunicarse con el proveedor de IA.",

          detail:
            error?.message ||
            String(error)

        },
        502
      );

    }


    /*
     * ----------------------------------------------------------
     * EXTRAER RESPUESTA
     * ----------------------------------------------------------
     */

    const answer =
      extraerRespuestaIA(
        aiResult
      );


    /*
     * ----------------------------------------------------------
     * SI NO HAY TEXTO
     * ----------------------------------------------------------
     */

    if (!answer) {

      console.error(
        "================================================"
      );

      console.error(
        "AI_EMPTY_RESPONSE"
      );

      console.error(
        JSON.stringify(
          aiResult
        ).slice(
          0,
          10000
        )
      );

      console.error(
        "================================================"
      );


      return json(
        {
          ok: false,

          code:
            "AI_EMPTY_RESPONSE",

          error:
            "Sofía recibió una respuesta del proveedor de IA, pero no se pudo extraer el texto.",

          diagnostic:

            aiResult
              ? {
                  tieneChoices:
                    Array.isArray(
                      aiResult.choices
                    ),

                  cantidadChoices:
                    Array.isArray(
                      aiResult.choices
                    )
                      ? aiResult.choices.length
                      : 0,

                  tieneResponse:
                    typeof
                      aiResult.response ===
                    "string",

                  tieneResult:
                    !!aiResult.result
                }

              : null

        },
        502
      );

    }


    /*
     * ----------------------------------------------------------
     * TODO CORRECTO
     * ----------------------------------------------------------
     */

    return json({

      ok:
        true,

      answer:
        answer,

      model:
        AI_MODEL,

      remaining:
        rate.remaining,

      user: {

        uid:
          user.uid,

        rol:
          user.rol

      }

    });

  }

};
