// proxy-serpro/lib/certificadoEscritorio.js
// Loader dinâmico de certificado A1 por escritório, com cache LRU em memória.
//
// Fluxo de obterContextoMtls(escritorioId):
//   1. Busca em certificados_escritorio o registro ativo do escritório.
//   2. Baixa o .pfx do bucket privado `certificados`.
//   3. Decifra senha_cifrada+iv com AES-GCM-256 (chave = SHA-256(CERT_ENCRYPTION_KEY)).
//      Algoritmo idêntico ao de supabase/functions/certificado-upload/index.ts,
//      só que invertido (decrypt em vez de encrypt).
//   4. Converte PKCS#12 → PEM via pfxToPem().
//   5. Cria undici Agent (mTLS).
//
// Cache:
//   - LRU por escritorio_id, max 20 entradas.
//   - TTL de revalidação 1h: passou disso, recarrega antes de usar.
//   - dedup de cargas concorrentes via inFlight Map<id, Promise>.
//   - tokenCache (access_token + jwt_token do Integra Contador) vive
//     dentro da entrada — cada escritório tem seu próprio cert no /authenticate.

import { createClient } from "@supabase/supabase-js";
import { Agent } from "undici";
import { createHash, webcrypto } from "node:crypto";
import { pfxToPem } from "./pfxToPem.js";

const MAX_CACHE = 20;
const TTL_MS = 60 * 60 * 1000; // 1h

const subtle = webcrypto.subtle;

let _supabase = null;
function supabaseAdmin() {
  if (_supabase) return _supabase;
  const url = process.env.SUPABASE_URL;
  const serviceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (!url || !serviceKey) {
    throw new Error(
      "SUPABASE_URL e SUPABASE_SERVICE_ROLE_KEY são obrigatórios para carregar certificados por escritório",
    );
  }
  _supabase = createClient(url, serviceKey, {
    auth: { persistSession: false, autoRefreshToken: false },
  });
  return _supabase;
}

/** @type {Map<string, CacheEntry>} */
const cache = new Map();
/** @type {Map<string, Promise<CacheEntry>>} */
const inFlight = new Map();

/**
 * @typedef {Object} CacheEntry
 * @property {string} escritorioId
 * @property {import("undici").Agent} agent
 * @property {{ accessToken: string|null, jwtToken: string|null, expiresAt: number }} tokenCache
 * @property {string} thumbprint
 * @property {string|null} titularCnpj
 * @property {string|null} validadeEm  ISO 8601
 * @property {number} loadedAt
 * @property {number} lastUsedAt
 */

/** Erro estruturado para o handler mapear em HTTP status. */
export class CertificadoError extends Error {
  /**
   * @param {string} code   ex: "certificado_nao_encontrado"
   * @param {number} status HTTP a devolver
   * @param {string} message
   */
  constructor(code, status, message) {
    super(message);
    this.code = code;
    this.status = status;
  }
}

/**
 * Devolve (ou carrega) o contexto mTLS de um escritório.
 * @param {string} escritorioId
 * @returns {Promise<CacheEntry>}
 */
export async function obterContextoMtls(escritorioId) {
  if (!escritorioId || typeof escritorioId !== "string") {
    throw new CertificadoError("escritorio_id_invalido", 400, "escritorio_id obrigatório");
  }

  const agora = Date.now();
  const cached = cache.get(escritorioId);
  if (cached && agora - cached.loadedAt < TTL_MS) {
    cached.lastUsedAt = agora;
    // re-insere para atualizar ordem do LRU
    cache.delete(escritorioId);
    cache.set(escritorioId, cached);
    return cached;
  }

  // dedup de cargas concorrentes
  const pendente = inFlight.get(escritorioId);
  if (pendente) return pendente;

  const promessa = carregarEntry(escritorioId)
    .then((entry) => {
      // remove versão antiga (e fecha o agent)
      const old = cache.get(escritorioId);
      if (old && old !== entry) old.agent.close().catch(() => {});
      cache.set(escritorioId, entry);
      evictSeNecessario();
      return entry;
    })
    .finally(() => {
      inFlight.delete(escritorioId);
    });
  inFlight.set(escritorioId, promessa);
  return promessa;
}

/** Invalida uma entrada (ou todas). Útil quando o usuário troca o cert ativo. */
export function invalidarCache({ escritorioId = null, all = false } = {}) {
  if (all) {
    for (const entry of cache.values()) {
      entry.agent.close().catch(() => {});
    }
    const n = cache.size;
    cache.clear();
    return { removidos: n };
  }
  if (escritorioId && cache.has(escritorioId)) {
    const entry = cache.get(escritorioId);
    entry.agent.close().catch(() => {});
    cache.delete(escritorioId);
    return { removidos: 1 };
  }
  return { removidos: 0 };
}

/** Snapshot do cache para o /healthz. */
export function snapshotCache() {
  return {
    size: cache.size,
    max: MAX_CACHE,
    entries: Array.from(cache.values()).map((e) => ({
      escritorio_id: e.escritorioId,
      thumbprint: e.thumbprint.slice(0, 16),
      titular_cnpj: e.titularCnpj,
      validade_em: e.validadeEm,
      loaded_at: new Date(e.loadedAt).toISOString(),
      last_used_at: new Date(e.lastUsedAt).toISOString(),
    })),
  };
}

// ====================== internas ======================

async function carregarEntry(escritorioId) {
  const sb = supabaseAdmin();

  // 1) Busca cert ativo do escritório
  const { data: cert, error: certErr } = await sb
    .from("certificados_escritorio")
    .select(
      "id, arquivo_path, senha_cifrada, iv, ativo, validade_em, titular_cnpj, thumbprint_sha256",
    )
    .eq("escritorio_id", escritorioId)
    .eq("ativo", true)
    .limit(1)
    .maybeSingle();

  if (certErr) {
    throw new CertificadoError(
      "erro_consulta_cert",
      500,
      `Falha ao consultar certificado: ${certErr.message}`,
    );
  }
  if (!cert) {
    throw new CertificadoError(
      "certificado_nao_encontrado",
      404,
      "Nenhum certificado A1 ativo para este escritório. Acesse /configuracoes para ativar um certificado.",
    );
  }

  // valida vencimento (cheap check antes de baixar)
  if (cert.validade_em && new Date(cert.validade_em).getTime() < Date.now()) {
    throw new CertificadoError(
      "certificado_vencido",
      410,
      `Certificado A1 vencido em ${cert.validade_em.slice(0, 10)}. Suba um novo em /configuracoes.`,
    );
  }

  // 2) Baixa o .pfx do storage
  const { data: blob, error: dlErr } = await sb.storage
    .from("certificados")
    .download(cert.arquivo_path);
  if (dlErr || !blob) {
    throw new CertificadoError(
      "erro_storage",
      502,
      `Falha ao baixar .pfx do storage: ${dlErr?.message ?? "desconhecido"}`,
    );
  }
  const pfxBuffer = Buffer.from(await blob.arrayBuffer());

  // 3) Decifra a senha (AES-GCM 256, chave = SHA-256(CERT_ENCRYPTION_KEY))
  const encKeyRaw = process.env.CERT_ENCRYPTION_KEY;
  if (!encKeyRaw) {
    throw new CertificadoError(
      "config_invalida",
      500,
      "CERT_ENCRYPTION_KEY não configurada no proxy",
    );
  }
  const senha = await decifrarSenha(cert.senha_cifrada, cert.iv, encKeyRaw);

  // 4) Converte PKCS#12 → PEM (vai lançar se senha errada)
  let pem;
  try {
    pem = pfxToPem(pfxBuffer, senha);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    throw new CertificadoError(
      "pfx_invalido",
      500,
      `Falha ao abrir PKCS#12 do escritório: ${msg}`,
    );
  }

  // 5) Cria agent mTLS
  const agent = new Agent({
    connect: {
      key: pem.pemKey,
      cert: pem.pemCert,
      ...(pem.pemCa.length > 0 ? { ca: pem.pemCa } : {}),
    },
  });

  const agora = Date.now();
  return {
    escritorioId,
    agent,
    tokenCache: { accessToken: null, jwtToken: null, expiresAt: 0 },
    thumbprint: pem.thumbprintSha256,
    titularCnpj: cert.titular_cnpj ?? pem.titularCnpj,
    validadeEm: cert.validade_em ?? (pem.validadeEm ? pem.validadeEm.toISOString() : null),
    loadedAt: agora,
    lastUsedAt: agora,
  };
}

function evictSeNecessario() {
  if (cache.size <= MAX_CACHE) return;
  // pega a entrada com lastUsedAt mais antigo
  let oldestId = null;
  let oldestAt = Infinity;
  for (const [id, entry] of cache.entries()) {
    if (entry.lastUsedAt < oldestAt) {
      oldestAt = entry.lastUsedAt;
      oldestId = id;
    }
  }
  if (oldestId) {
    const e = cache.get(oldestId);
    e.agent.close().catch(() => {});
    cache.delete(oldestId);
  }
}

/**
 * Decifra a senha cifrada com cifrarSenha() da edge function certificado-upload.
 * Algoritmo: AES-GCM-256, chave = SHA-256(chaveBase), IV de 12 bytes.
 * @param {unknown} cifradoIn  bytea do banco (pode vir como string "\\xHEX",
 *                             Uint8Array, ou Buffer)
 * @param {unknown} ivIn       idem
 * @param {string} chaveBase
 */
async function decifrarSenha(cifradoIn, ivIn, chaveBase) {
  const cifrado = byteaParaBytes(cifradoIn);
  const iv = byteaParaBytes(ivIn);
  if (iv.length !== 12) {
    throw new CertificadoError(
      "iv_invalido",
      500,
      `IV do certificado deve ter 12 bytes (recebido ${iv.length})`,
    );
  }

  const enc = new TextEncoder();
  const keyMaterial = await subtle.digest("SHA-256", enc.encode(chaveBase));
  const key = await subtle.importKey(
    "raw",
    keyMaterial,
    { name: "AES-GCM" },
    false,
    ["decrypt"],
  );
  const plain = await subtle.decrypt({ name: "AES-GCM", iv }, key, cifrado);
  return new TextDecoder().decode(plain);
}

/**
 * Converte um valor `bytea` lido pelo supabase-js em Uint8Array.
 * supabase-js devolve `bytea` como string `\xHEX` (formato hex do Postgres)
 * ou, em alguns casos, já como base64. Aceita também Buffer/Uint8Array.
 */
function byteaParaBytes(v) {
  if (v == null) {
    throw new CertificadoError("cert_corrompido", 500, "campo bytea nulo");
  }
  if (v instanceof Uint8Array) return v;
  if (Buffer.isBuffer?.(v)) return new Uint8Array(v);
  if (typeof v === "string") {
    if (v.startsWith("\\x") || v.startsWith("\\X")) {
      const hex = v.slice(2);
      return Uint8Array.from(Buffer.from(hex, "hex"));
    }
    // fallback: hex puro
    if (/^[0-9a-fA-F]+$/.test(v) && v.length % 2 === 0) {
      return Uint8Array.from(Buffer.from(v, "hex"));
    }
    // fallback: base64
    try {
      return Uint8Array.from(Buffer.from(v, "base64"));
    } catch {
      // cai no throw abaixo
    }
  }
  throw new CertificadoError(
    "cert_corrompido",
    500,
    "formato de bytea desconhecido",
  );
}
